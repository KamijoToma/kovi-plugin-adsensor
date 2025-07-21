//! This plugin is designed to prevent spam messages in groups by requiring users to react to a message before they can send messages.
//!
//! Support only **Kovi Bot** and **NapCat** backend.
//!
//! Author: KamijoToma(GitHub)
//!
//! This file is licensed under the Apache License, Version 2.0 (the "License");
//! you may not use this file except in compliance with the License.
//!
//! Usage:
//! 1. Add this plugin to your Kovi bot (https://github.com/ThriceCola/Kovi) and configure the OneBot backend (we use NapCat).
//! 2. Configure the plugin by creating a `config.toml` file in the bot's data directory with the following content:
//! ```toml
//! kick_timeout = 300
//! ```
//! 3. The `kick_timeout` value is the time in seconds after which a user will be kicked if they do not react to the message.

use config::{Config, ConfigError};
use kovi::bot::runtimebot::onebot_api::AddRequestType;
use kovi::event::GroupMsgEvent;
use kovi::{
    Message, NoticeEvent, PluginBuilder as plugin, PluginBuilder, RequestEvent, RuntimeBot, log,
    serde_json, tokio,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, RwLock};
use std::time::Duration;

type GroupId = i64;
type UserId = i64;

lazy_static! {
    static ref BOT: Arc<RuntimeBot> = PluginBuilder::get_runtime_bot();
    static ref GROUP_REACTIONS: Arc<RwLock<HashMap<GroupId, HashMap<UserId, MessageReaction>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

static mut CONFIG_KICK_TIMEOUT: u64 = 300;

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

/// Load the plugin configuration from a `config.toml` file in the bot's data directory.
fn load_plugin_config() -> Result<PluginConfig, ConfigError> {
    let config_path = BOT.get_data_path().join("config.toml");
    let config_ = Config::builder()
        .add_source(config::File::new(
            config_path.to_str().unwrap(),
            config::FileFormat::Toml,
        ))
        .build()?;
    let config: PluginConfig = config_.try_deserialize()?;
    Ok(config)
}

/// Load group reactions from a JSON file in the bot's data directory.
fn load_group_reactions_from_file()
-> Result<HashMap<GroupId, HashMap<UserId, MessageReaction>>, Box<dyn Error>> {
    let group_reactions_path = BOT.get_data_path().join("group_reactions.json");
    if !group_reactions_path.exists() {
        return Ok(HashMap::new());
    }
    let group_reactions_str = std::fs::read_to_string(group_reactions_path)?;
    let group_reactions: HashMap<GroupId, HashMap<UserId, MessageReaction>> =
        serde_json::from_str(&group_reactions_str)?;
    Ok(group_reactions)
}

/// Save group reactions to a JSON file in the bot's data directory.
fn save_group_reactions_to_file(
    group_reactions: &HashMap<GroupId, HashMap<UserId, MessageReaction>>,
) -> Result<(), std::io::Error> {
    let group_reactions_path = BOT.get_data_path().join("group_reactions.json");
    let group_reactions_str = serde_json::to_string(group_reactions)?;
    std::fs::write(group_reactions_path, group_reactions_str)?;
    Ok(())
}

/// Spawn an async task to kick a user after a delay if they have not reacted to the message.
fn spawn_kick_user_after_delay(group_id: GroupId, user_id: UserId, delay: Duration) {
    let bot = BOT.clone();
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let inventor_user_id;
        // Check if the user has reacted to the message
        let group_reactions = GROUP_REACTIONS.read().unwrap();
        if let Some(user_reactions) = group_reactions.get(&group_id) {
            if let Some(message_reaction) = user_reactions.get(&user_id) {
                // User has reacted, do nothing
                log::info!(
                    "User {user_id} has not reacted to the message in group {group_id}, kicking them out"
                );
                inventor_user_id = message_reaction.invitor_user_id;
            } else {
                log::info!(
                    "User {user_id} has reacted to the message in group {group_id}, not kicking them out"
                );
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

/// Handle group join requests by automatically approving them.
async fn handler_group_join_request(event: Arc<RequestEvent>) {
    // Handle group join requests
    log::info!(
        "Received on request: {:?}, type={}",
        event,
        event.request_type
    );
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

    let flag_str = original_obj.get("flag").and_then(|id| id.as_str());
    if flag_str.is_none() {
        log::warn!("Request without flag");
        return;
    }
    let flag_str = flag_str.unwrap();

    let sub_type_str = original_obj.get("sub_type").and_then(|id| id.as_str());
    if sub_type_str.is_none() {
        log::warn!("Request without sub_type");
        return;
    }
    let sub_type_str = sub_type_str.unwrap();

    // Approve the request
    BOT.set_group_add_request(
        flag_str,
        AddRequestType::SubType(sub_type_str),
        true,
        "Bot auto agree",
    );
}

async fn handler_message_of_unapproved_member(event: Arc<GroupMsgEvent>) {
    let group_id = event.group_id;
    let user_id = event.user_id;
    let message_id = event.message_id;

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
}

async fn handler_group_msg_emoji_like_notice(event: Arc<NoticeEvent>) {
    let original_obj = match event.original_json.as_object() {
        Some(obj) => obj,
        None => {
            log::warn!("Received notice without original JSON");
            return;
        }
    };

    if original_obj
        .get("notice_type")
        .and_then(|id| id.as_str())
        .is_none_or(|s| s != "group_msg_emoji_like")
    {
        return;
    }

    let group_id = original_obj.get("group_id").and_then(|id| id.as_i64());
    if group_id.is_none() {
        log::warn!("Notice without group_id");
        return;
    }
    let group_id = group_id.unwrap();

    let user_id = original_obj.get("user_id").and_then(|id| id.as_i64());
    if user_id.is_none() {
        log::warn!("Notice without user_id");
        return;
    }
    let user_id = user_id.unwrap();

    let message_id = original_obj.get("message_id").and_then(|id| id.as_i64());
    if message_id.is_none() {
        log::warn!("Notice without message_id");
        return;
    }
    let message_id = message_id.unwrap() as i32;

    // Check if the user is an admin or owner
    let user_is_admin = group_member_is_admin(group_id, user_id).await;

    // Check if the reaction message is in GROUP_REACTIONS
    let mut custom_message_str = None;
    let group_reactions = GROUP_REACTIONS.read().unwrap();
    let remove_user_id: Option<UserId> = if let Some(user_reactions) =
        group_reactions.get(&group_id)
    {
        if let Some(reaction) = user_reactions.get(&user_id) {
            // Check if the reaction message is the same as the last one
            if reaction.message_id == message_id {
                // Remove the reaction message from GROUP_REACTIONS
                log::info!(
                    "Removing reaction message {message_id} in group {group_id} from user {user_id}"
                );
                Some(user_id)
            } else {
                None
            }
        } else if user_is_admin {
            // Find if this message is a reaction message, if so, remove it
            if let Some(m) = user_reactions.iter().find_map(|(k, r)| {
                if r.message_id == message_id {
                    Some(*k)
                } else {
                    None
                }
            }) {
                log::info!(
                    "Admin {user_id} clicked reaction message {message_id} in group {group_id}"
                );
                custom_message_str =
                    Some(" 管理员点按 reaction，已解禁，你可以自由发言了。".to_string());
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
                log::info!(
                    "User {user_id} is an invitor of other member, removing reaction message {message_id} in group {group_id}"
                );
                custom_message_str =
                    Some(" 邀请人点按 reaction 解禁，你可以自由发言了。".to_string());
                Some(m)
            } else {
                None
            }
        }
    } else {
        None
    };
    drop(group_reactions);
    if let Some(user_id) = remove_user_id {
        let mut group_reactions = GROUP_REACTIONS.write().unwrap();
        if let Some(user_reactions) = group_reactions.get_mut(&group_id) {
            let reaction_item = user_reactions.remove(&user_id);
            // Send a message to the group to notify that the reaction was removed
            let mut message = Message::new();
            message.push_at(user_id.to_string().as_str());
            if let Some(custom_message) = custom_message_str {
                message.push_text(custom_message);
            } else {
                message.push_text(" 感谢点按 reaction，已解禁，你可以自由发言了。");
            }
            BOT.send_group_msg(group_id, message);
            // Revoke the reaction message
            if let Some(reaction) = reaction_item {
                BOT.delete_msg(reaction.message_id);
            } else {
                log::warn!("No reaction message found for user {user_id} in group {group_id}");
            }
        }
    }
}

async fn handler_group_new_member_join_notice(event: Arc<NoticeEvent>) {
    let original_obj = match event.original_json.as_object() {
        Some(obj) => obj,
        None => {
            log::warn!("Received notice without original JSON");
            return;
        }
    };

    let notice_type = original_obj.get("notice_type").and_then(|id| id.as_str());
    if notice_type.is_none() {
        log::warn!("Notice without notice_type");
        return;
    }
    let notice_type = notice_type.unwrap();

    if notice_type != "group_increase" {
        return;
    }

    let group_id = original_obj.get("group_id").and_then(|id| id.as_i64());
    if group_id.is_none() {
        log::warn!("Notice without group_id");
        return;
    }
    let group_id = group_id.unwrap();

    let user_id = original_obj.get("user_id").and_then(|id| id.as_i64());
    if user_id.is_none() {
        log::warn!("Notice without user_id");
        return;
    }
    let user_id = user_id.unwrap();
    
    let sub_type = original_obj.get("sub_type").and_then(|id| id.as_str());
    if sub_type.is_none() {
        log::warn!("Notice without sub_type");
        return;
    }
    let sub_type = sub_type.unwrap();

    let invitor_user_id = if sub_type == "invite" {
        original_obj.get("operator_id").and_then(|id| id.as_i64())
    } else {
        None
    };

    if let Some(invitor_user_id) = invitor_user_id
        && group_member_is_admin(group_id, invitor_user_id).await
    {
        log::info!("Admin invited user. No captcha required.");
        let mut message = Message::new();
        message.push_at(user_id.to_string().as_str());
        message.push_text(
            " 欢迎你加入群聊！由于你是被管理员邀请加入群聊，你无需进行任何操作即可发言。",
        );
        BOT.send_group_msg(group_id, message);
        return;
    }

    // Wait 2s to ensure the user data is synced to the bot.
    // workaround for the AT message below.
    // Instantly sending a message may cause the At message to not recognize the user.
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Send a welcome message
    let mut message = Message::new();
    message.push_at(user_id.to_string().as_str());
    message.push_text(" 欢迎 ");
    message.push_text(format!("{user_id} 加入群聊！请注意，为了防止 spam 信息传播，请你给此条消息点按任意 reaction 解禁（长按本消息并点击上方弹出的任意表情），否则你发布的所有消息均将被撤回并在一段时间后被踢出群聊。"));
    if let Some(invitor_user_id) = invitor_user_id {
        message.push_text(format!(
            "你是由 {invitor_user_id} 邀请加入群聊的，如果未通过验证，你的邀请人将被一并踢出群聊。"
        ));
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
        user_reactions.insert(
            user_id,
            MessageReaction {
                message_id: reaction_message_id,
                start_time: chrono::Local::now(),
                invitor_user_id,
            },
        );
    }
    unsafe {
        spawn_kick_user_after_delay(group_id, user_id, Duration::from_secs(CONFIG_KICK_TIMEOUT));
    }
}

#[kovi::plugin]
async fn main() {
    let config = load_plugin_config().unwrap();
    // Load existing group reactions from file
    let group_reactions = load_group_reactions_from_file().unwrap();
    {
        // Use a block to limit the scope of the write lock
        let mut reactions_lock = GROUP_REACTIONS.write().unwrap();
        *reactions_lock = group_reactions;
    }

    // When the plugin is unloaded, save the group reactions to file
    PluginBuilder::drop(|| async {
        // Save group reactions to file on plugin unload
        let group_reactions = GROUP_REACTIONS.read().unwrap();
        if let Err(e) = save_group_reactions_to_file(&group_reactions) {
            log::error!("Failed to save group reactions to file: {e}");
        }
    });

    plugin::on_request(handler_group_join_request);
    plugin::on_group_msg(handler_message_of_unapproved_member);

    plugin::on_notice(handler_group_msg_emoji_like_notice);

    unsafe {
        CONFIG_KICK_TIMEOUT = config.kick_timeout;
    }

    plugin::on_notice(handler_group_new_member_join_notice);
}

async fn get_group_member_role(group_id: GroupId, user_id: UserId) -> Option<String> {
    let member_info = BOT.get_group_member_info(group_id, user_id, false).await;
    member_info
        .ok()?
        .data
        .as_object()
        .and_then(|data| data.get("role"))
        .and_then(|role| role.as_str())
        .map(|role_str| role_str.to_string())
}

async fn group_member_is_admin(group_id: GroupId, user_id: UserId) -> bool {
    match get_group_member_role(group_id, user_id).await {
        Some(role) => role == "admin" || role == "owner",
        None => false,
    }
}
