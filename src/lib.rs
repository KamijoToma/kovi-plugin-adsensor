/// This plugin is designed to prevent spam messages in groups by requiring users to react to a message before they can send messages.
///
/// Support only **Kovi Bot** and **NapCat** backend.
///
/// Author: KamijoToma(Github)
///
/// This file is licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
///
/// Usage:
/// 1. Add this plugin to your Kovi bot (https://github.com/ThriceCola/Kovi) and configure the OneBot backend (we use NapCat).
/// 2. Configure the plugin by creating a `config.toml` file in the bot's data directory with the following content:
/// ```toml
/// kick_timeout = 300
/// ```
/// 3. The `kick_timeout` value is the time in seconds after which a user will be kicked if they do not react to the message.

use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use config::{Config, ConfigError};
use kovi::{log, serde_json, tokio, ApiReturn, Message, PluginBuilder as plugin, PluginBuilder, RuntimeBot};
use kovi::bot::runtimebot::onebot_api::AddRequestType;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

type GroupId = i64;
type UserId = i64;

lazy_static! {
    static ref BOT: Arc<RuntimeBot> = PluginBuilder::get_runtime_bot();
    static ref GROUP_REACTIONS: Arc<RwLock<HashMap<GroupId, HashMap<UserId, MessageReaction>>>> = Arc::new(RwLock::new(HashMap::new()));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PluginConfig {
    /// kick timeout in seconds
    kick_timeout: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MessageReaction {
    message_id: i32,
    start_time: chrono::DateTime<chrono::Local>,
    invitor_user_id: Option<UserId>,
}

fn load_config() -> Result<PluginConfig, ConfigError> {
    let config_path = BOT.get_data_path().join("config.toml");
    let config_ = Config::builder()
        .add_source(config::File::new(config_path.to_str().unwrap(), config::FileFormat::Toml))
        .build()?;
    let config: PluginConfig = config_.try_deserialize()?;
    Ok(config)
}

fn load_group_reactions_from_file() -> Result<HashMap<GroupId, HashMap<UserId, MessageReaction>>, Box<dyn Error>> {
    let group_reactions_path = BOT.get_data_path().join("group_reactions.json");
    if !group_reactions_path.exists() {
        return Ok(HashMap::new());
    }
    let group_reactions_str = std::fs::read_to_string(group_reactions_path)?;
    let group_reactions: HashMap<GroupId, HashMap<UserId, MessageReaction>> = serde_json::from_str(&group_reactions_str)?;
    Ok(group_reactions)
}

fn save_group_reactions_to_file(group_reactions: &HashMap<GroupId, HashMap<UserId, MessageReaction>>) -> Result<(), std::io::Error> {
    let group_reactions_path = BOT.get_data_path().join("group_reactions.json");
    let group_reactions_str = serde_json::to_string(group_reactions)?;
    std::fs::write(group_reactions_path, group_reactions_str)?;
    Ok(())
}

fn spawn_kick_user_after_delay(
    group_id: GroupId,
    user_id: UserId,
    delay: Duration,
) {
    let bot = BOT.clone();
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let inventor_user_id;
        // Check if the user has reacted to the message
        let group_reactions = GROUP_REACTIONS.read().unwrap();
        if let Some(user_reactions) = group_reactions.get(&group_id) {
            if let Some(message_reaction) = user_reactions.get(&user_id) {
                // User has reacted, do nothing
                log::info!("User {user_id} has not reacted to the message in group {group_id}, kicking them out");
                inventor_user_id = message_reaction.invitor_user_id;
            } else { 
                log::info!("User {user_id} has reacted to the message in group {group_id}, not kicking them out");
                return;
            }
        } else {
            log::warn!("No reactions found for group {group_id}");
            return;
        }
        
        bot.set_group_kick(group_id, user_id, false);
        if let Some(invitor_user_id) = inventor_user_id {
            // kick the invitor user as well
            bot.set_group_kick(group_id, invitor_user_id, false);
        }
    });
}

#[kovi::plugin]
async fn main() {
    let config = load_config().unwrap();
    // Load existing group reactions from file
    let group_reactions = load_group_reactions_from_file().unwrap();
    {
        let mut reactions_lock = GROUP_REACTIONS.write().unwrap();
        *reactions_lock = group_reactions;
    }
    PluginBuilder::drop(|| async {
        // Save group reactions to file on plugin unload
        let group_reactions = GROUP_REACTIONS.read().unwrap();
        if let Err(e) = save_group_reactions_to_file(&group_reactions) {
            log::error!("Failed to save group reactions to file: {e}");
        }
    });

    plugin::on_request(|event| async move {
        // Handle group join requests
        log::info!("Received on request: {:?}, type={}", event, event.request_type);
        if event.request_type != "group" {
            return;
        }
        log::info!("Received a group request");
        let original_obj = match event.original_json.as_object() {
            Some(obj) => obj,
            None => {
                log::warn!("Received request without original JSON");
                return;
            }
        };

        let flag_str = match original_obj.get("flag") {
            Some(flag) => match flag.as_str() {
                Some(flag) => flag,
                None => {
                    log::warn!("flag is not a string");
                    return;
                }
            },
            None => {
                log::warn!("Request without flag");
                return;
            }
        };
        let sub_type_str = match original_obj.get("sub_type") {
            Some(sub_type) => match sub_type.as_str() {
                Some(sub_type) => sub_type,
                None => {
                    log::warn!("sub_type is not a string");
                    return;
                }
            },
            None => {
                log::warn!("Request without sub_type");
                return;
            }
        };
        // Approve the request
        BOT.set_group_add_request(flag_str, AddRequestType::SubType(sub_type_str), true, "Bot auto agree");
        
    });

    plugin::on_group_msg(|msg_event| async move {
        let group_id = msg_event.group_id;
        let user_id = msg_event.user_id;
        let message_id = msg_event.message_id;

        // Check if group_id and user_id are in GROUP_REACTIONS
        let group_reactions = GROUP_REACTIONS.read().unwrap();
        if let Some(user_reactions) = group_reactions.get(&group_id) {
            if user_reactions.get(&user_id).is_some() {
                // Have valid reaction wait item
                // revoke the message
                BOT.delete_msg(message_id);
                log::info!("Revoked message {message_id} in group {group_id} from user {user_id}");
            }
        }
    });

    plugin::on_notice(|event| async move {
        let original_obj = match event.original_json.as_object() {
            Some(obj) => obj,
            None => {
                log::warn!("Received notice without original JSON");
                return;
            }
        };
        let _ = match original_obj.get("notice_type") {
            Some(notice_type) => match notice_type.as_str() {
                Some(notice_type) => if notice_type == "group_msg_emoji_like" {
                    "group_msg_emoji_like"
                } else {
                    // Not an emoji like event, ignore
                    return;
                },
                None => {
                    log::warn!("notice_type is not a string");
                    return;
                }
            },
            None => {
                log::warn!("Notice without sub_type");
                return;
            }
        };
        let group_id = match original_obj.get("group_id") {
            Some(id) => match id.as_i64() {
                Some(id) => id,
                None => {
                    log::warn!("group_id is not an integer");
                    return;
                }
            },
            None => {
                log::warn!("Notice without group_id");
                return;
            }
        };
        let user_id = match original_obj.get("user_id") {
            Some(id) => match id.as_i64() {
                Some(id) => id,
                None => {
                    log::warn!("user_id is not an integer");
                    return;
                }
            },
            None => {
                log::warn!("Notice without user_id");
                return;
            }
        };

        let message_id = match original_obj.get("message_id") {
            Some(id) => match id.as_i64() {
                Some(id) => id as i32,
                None => {
                    log::warn!("message_id is not an integer");
                    return;
                }
            },
            None => {
                log::warn!("Notice without message_id");
                return;
            }
        };

        // Check if the user is an admin or owner
        let user_is_admin = match get_group_member_role(group_id, user_id).await {
            Ok(Some(role)) => role == "admin" || role == "owner",
            _ => false
        };

        // Check if the reaction message is in GROUP_REACTIONS
        let group_reactions = GROUP_REACTIONS.read().unwrap();
        let remove_user_id: Option<UserId> = if let Some(user_reactions) = group_reactions.get(&group_id) {
            if let Some(reaction) = user_reactions.get(&user_id) {
                // Check if the reaction message is the same as the last one
                if reaction.message_id == message_id {
                    // Remove the reaction message from GROUP_REACTIONS
                    log::info!("Removing reaction message {message_id} in group {group_id} from user {user_id}");
                    Some(user_id)
                } else {
                    None
                }
            } else {
                if user_is_admin {
                    // Find if this message is a reaction message, if so, remove it
                    if let Some(m) = user_reactions.iter().find_map(|(k, r)| if r.message_id == message_id { Some(*k)} else { None}) {
                        log::info!("Admin {user_id} removed reaction message {message_id} in group {group_id}");
                        Some(m)
                    } else {
                        None
                    }
                } else {
                    // Find if the user is an invitor of other member, if so, remove it
                    if let Some(m) = user_reactions.iter().find_map(|(k, r)| {
                        if let Some(invitor_user_id) = r.invitor_user_id {
                            if invitor_user_id == user_id {
                                Some(*k)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }) {
                        log::info!("User {user_id} is an invitor of other member, removing reaction message {message_id} in group {group_id}");
                        Some(m)
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        };
        drop(group_reactions);
        if let Some(user_id) = remove_user_id {
            let mut group_reactions = GROUP_REACTIONS.write().unwrap();
            if let Some(user_reactions) = group_reactions.get_mut(&group_id) {
                user_reactions.remove(&user_id);
                // Send a message to the group to notify that the reaction was removed
                let mut message = Message::new();
                message.push_at(user_id.to_string().as_str());
                message.push_text(" 感谢点按 reaction，已解禁，你可以自由发言了。");
                BOT.send_group_msg(group_id, message);
            }
        }
    });

    let kick_timeout = config.kick_timeout;
    
    plugin::on_notice(move |event| async move {
        let original_obj = match event.original_json.as_object() {
            Some(obj) => obj,
            None => {
                log::warn!("Received notice without original JSON");
                return;
            }
        };
        let notice_type = match original_obj.get("notice_type") {
            Some(notice_type) => match notice_type.as_str() {
                Some(notice_type) => notice_type,
                None => {
                    log::warn!("notice_type is not a string");
                    return;
                }
            },
            None => {
                log::warn!("Notice without notice_type");
                return;
            }
        };
        
        if notice_type != "group_increase" {
            return;
        }
        
        let group_id = match original_obj.get("group_id") {
            Some(id) => match id.as_i64() {
                Some(id) => id,
                None => {
                    log::warn!("group_id is not an integer");
                    return;
                }
            },
            None => {
                log::warn!("Notice without group_id");
                return;
            }
        };
        
        let user_id = match original_obj.get("user_id") {
            Some(id) => match id.as_i64() {
                Some(id) => id,
                None => {
                    log::warn!("user_id is not an integer");
                    return;
                }
            },
            None => {
                log::warn!("Notice without user_id");
                return;
            }
        };

        let sub_type = match original_obj.get("sub_type") {
            Some(sub_type) => match sub_type.as_str() {
                Some(sub_type) => sub_type,
                None => {
                    log::warn!("sub_type is not a string");
                    return;
                }
            },
            None => {
                log::warn!("Notice without sub_type");
                return;
            }
        };

        let inventor_user_id: Option<UserId> = if sub_type == "invite" {
            match original_obj.get("operator_id") {
                Some(id) => match id.as_i64() {
                    Some(id) => Some(id),
                    None => {
                        log::warn!("invitor_user_id is not an integer");
                        None
                    }
                },
                None => {
                    log::warn!("Notice without invitor_user_id");
                    None
                }
            }
        } else {
            None
        };

        if inventor_user_id.is_some() && let Ok(inventor_user_info) = BOT.get_group_member_info(group_id, inventor_user_id.unwrap(), false).await {
            if let Some(resp_obj) = inventor_user_info.data.as_object() {
                if let Some(role) = resp_obj.get("role") {
                    if role.as_str() != Some("owner") && role.as_str() != Some("admin") {
                        log::info!("Admin invited user. No captcha required.");
                        let mut message = Message::new();
                        message.push_at(user_id.to_string().as_str());
                        message.push_text(" 欢迎你加入群聊！由于你是被管理员邀请加入群聊，你无需进行任何操作即可发言。");
                        BOT.send_group_msg(group_id, message);
                        return;
                    }
                }
            }
        }

        // Wait 2s
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // Send a welcome message
        let mut message = Message::new();
        message.push_at(user_id.to_string().as_str());
        message.push_text(" 欢迎 ");
        message.push_text(format!("{user_id} 加入群聊！请注意，为了防止 spam 信息传播，请你给此条消息点按任意 reaction 解禁（长按本消息并点击上方弹出的任意表情），否则你发布的所有消息均将被撤回并在一段时间后被踢出群聊。"));
        if let Some(invitor_user_id) = inventor_user_id {
            message.push_text(format!("你是由 {} 邀请加入群聊的，如果你未通过验证，邀请人将被一并踢出群聊。", invitor_user_id));
        }
        let reaction_message_id = match BOT.send_group_msg_return(group_id, message).await {
            Ok(msg_id) => msg_id,
            Err(e) => {
                log::error!("Failed to send welcome message: {e}");
                return;
            }
        };
        // Insert the reaction message into the map
        {
            let mut group_reactions = GROUP_REACTIONS.write().unwrap();
            let user_reactions = group_reactions.entry(group_id).or_default();
            user_reactions.insert(user_id, MessageReaction {
                message_id: reaction_message_id,
                start_time: chrono::Local::now(),
                invitor_user_id: inventor_user_id,
            });
        }
        spawn_kick_user_after_delay(group_id, user_id, Duration::from_secs(kick_timeout));
    })
}

async fn get_group_member_role(
    group_id: GroupId,
    user_id: UserId,
) -> Result<Option<String>, ApiReturn> {
    let member_info = BOT.get_group_member_info(group_id, user_id, false).await?;
    if let Some(data) = member_info.data.as_object() {
        if let Some(role) = data.get("role") {
            if let Some(role_str) = role.as_str() {
                return Ok(Some(role_str.to_string()));
            }
        }
    }
    Ok(None)
}
