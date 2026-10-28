//! Admin-only service creation; identity and Bot marker commit in the same store.
use super::{
    CreateUserInput,
    helpers::{consolidate_attributes, unpack_attributes},
};
use crate::api::Context;
use juniper::{FieldError, FieldResult};
use lldap_access_control::{AdminBackendHandler, UserReadableBackendHandler};
use lldap_domain::{
    public_schema::PublicSchema,
    requests::CreateUserRequest,
    types::{Email, UserId, Uuid},
};
use lldap_domain_handlers::handler::BackendHandler;
use std::sync::Arc;

fn failure(error: impl std::fmt::Display) -> FieldError {
    let error_id = uuid::Uuid::new_v4();
    tracing::error!(%error_id, %error, "Service user creation failed");
    FieldError::from(format!("Service user creation failed; error_id={error_id}"))
}

fn request(user: CreateUserInput, schema: &PublicSchema) -> FieldResult<CreateUserRequest> {
    let attributes = consolidate_attributes(
        user.attributes.unwrap_or_default(),
        user.first_name,
        user.last_name,
        user.avatar,
    );
    let unpacked = unpack_attributes(attributes, schema, true)?;
    Ok(CreateUserRequest {
        user_id: UserId::new(&user.id),
        email: user
            .email
            .map(Email::from)
            .or(unpacked.email)
            .ok_or_else(|| FieldError::from("Email is required when creating a service user"))?,
        display_name: user.display_name.or(unpacked.display_name),
        attributes: unpacked.attributes,
    })
}

pub async fn create<Handler: BackendHandler>(
    context: &Context<Handler>,
    user: CreateUserInput,
    expected_bot_group_uuid: String,
) -> FieldResult<crate::query::User<Handler>> {
    let handler = context
        .get_admin_handler()
        .ok_or_else(|| FieldError::from("Unauthorized service user creation"))?;
    let marker = Uuid::try_from(expected_bot_group_uuid.as_str())
        .map_err(|_| FieldError::from("Canonical Bot marker UUID required"))?;
    if marker.as_str() != expected_bot_group_uuid
        || marker.as_str() == "00000000-0000-0000-0000-000000000000"
    {
        return Err(FieldError::from("Canonical Bot marker UUID required"));
    }
    let schema = handler.get_schema().await.map_err(failure)?;
    let request = request(user, &schema)?;
    let user_id = request.user_id.clone();
    let marker_uuid = marker.clone();
    handler
        .create_service_user(request, marker)
        .await
        .map_err(failure)?;
    tracing::info!(actor = %context.validation_result.user, subject = %user_id,
        bot_group_uuid = %marker_uuid, "Service user and Bot marker committed");
    let persisted = handler.get_user_details(&user_id).await.map_err(failure)?;
    crate::query::User::<Handler>::from_user(persisted, Arc::new(schema))
}
