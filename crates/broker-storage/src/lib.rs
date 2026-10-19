//! Server-owned storage credentials derived from actual SQL storage admission.
mod aws;
mod filesystem_session;
mod issued;
pub use aws::{
    AwsCredentialSource, AwsEndpointTransport, AwsStorageIssuer, AwsStorageRoute,
    AwsStorageRouteConfig, PrivateStaticCredentials,
};

pub use filesystem_session::{
    FilesystemSessionError, FilesystemStorageIssuer, FilesystemStorageRoute,
    FilesystemStorageRouteConfig, VerifiedFilesystemSession,
};
pub use issued::{IssuedStorageCredentials, StorageCopyIfNotExists, StorageIssueError};
mod service;
pub use service::{StorageCredentialsService, StorageIssuer};

mod filesystem_gateway;
mod filesystem_listing;
pub use filesystem_gateway::{FilesystemGateway, FilesystemGatewayConfig, FilesystemGatewayError};
mod filesystem_multipart;
mod filesystem_store;
pub use filesystem_listing::{
    FilesystemCopyOptions, FilesystemDeleteResult, FilesystemListEncoding, FilesystemListPage,
    FilesystemListRequest, FilesystemListedObject,
};
pub use filesystem_multipart::{
    FilesystemCompleteUpload, FilesystemCompletedPart, FilesystemPartInfo, FilesystemPartsPage,
    FilesystemPartsRequest,
};
pub use filesystem_store::{
    FilesystemConditions, FilesystemObjectInfo, FilesystemObjectRead, FilesystemPutOptions,
    FilesystemRequest, FilesystemStore, FilesystemStoreConfig, FilesystemStoreError,
};

mod hub_catalog;
pub use hub_catalog::{HubCatalogError, HubCatalogPage, HubCatalogQuery, HubCatalogReader};
