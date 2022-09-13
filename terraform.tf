##################################
# EDIT THE FOLLOWING PARAMETERS
#
# project_id :                  GCP project to be onboarded
#                               Prisma Cloud's service account will be created in this project
# flowlog_bucket_name :          GCP storage bucket name which will gather network flowlog data
# authentication_type :          Which method of On-Boarding is used by user at Prisma Cloud. Direct Access through Service Account Credential JSON File (service_account) or Federated Access through Workload Identity Federation (external_account)
#     Allowed Values (str) -> service_account / external_account
# prisma_aws_account_id:        Numeric Account ID of the AWS Stack Prisma Cloud Uses to get

variable "project_id" {
  type = string
  default = "prismadefenders"
}

variable "flowlog_bucket_name_project" {
  type = string
  default = ""
}

variable "protection_mode_proj" {
  type = string
  default = "monitor"
}

variable "is_compute_enabled" {
  type = string
  default = "false"
}

variable "authentication_type" {
  type = string
  default = "service_account"  # Allowed valued: service_account / external_account
  description = "Which method of On-Boarding is used by user at Prisma Cloud. Direct Access through Service Account Credential JSON File (service_account_json) or Federated Access through Workload Identity Federation"

  validation {
    condition = can(regex("^service_account|external_account$", var.authentication_type))
    error_message = "Invalid Value for OnBoarding Method. It can either be service_account or external_account. Please contact Prisma Cloud Support."
  }
}

variable "prisma_aws_account_id" {
  type    = string
  default = "188619942792"
  description = "AWS Cloud Account used by Prisma Cloud to get Federated access to user's resources"

  validation {
    condition = can(regex("[[:digit:]]|188619942792", var.prisma_aws_account_id))
    error_message = "Invalid Value for Prisma AWS Account ID. Please contact Prisma Cloud Support."
  }
}

variable "global_identifier" {
  type    = string
  default = "prisma-cloud"
  description = "Reflects in Customer Account. Can be changed to obliviate the phrase Prisma"
}

variable "global_identifier_friendly_name" {
  type    = string
  default = "Prisma Cloud"
}

# The list of permissions added to the custom role (Case sensitive)
variable "custom_role_permissions_monitor_proj" {
  type = list(string)
  default = [
    "storage.buckets.get",
    "storage.buckets.getIamPolicy",
    "pubsub.topics.getIamPolicy",
    "pubsub.subscriptions.getIamPolicy",
    "pubsub.snapshots.getIamPolicy",
    "cloudsecurityscanner.scans.list",
    "firebaserules.rulesets.get",
    "clientauthconfig.clients.listWithSecrets"
  ]
}

variable "custom_role_permissions_protect_proj" {
  type = list(string)
  default = [
    "container.clusters.update",
    "compute.instances.setMetadata",
    "storage.buckets.update",
    "compute.firewalls.update",
    "compute.firewalls.delete",
    "compute.networks.updatePolicy",
    "compute.subnetworks.update",
    "compute.disks.create",
    "compute.images.get",
    "compute.images.list",
    "compute.images.useReadOnly",
    "compute.instances.create",
    "compute.instances.delete",
    "compute.instances.get",
    "compute.instances.list",
    "compute.instances.setTags",
    "compute.networks.get",
    "compute.networks.use",
    "compute.networks.useExternalIp",
    "compute.subnetworks.use",
    "compute.subnetworks.useExternalIp"
  ]
}
variable "compute_role_permissions_proj" {
  type = list(string)
  default = [
    "compute.zones.list",
    "compute.instances.list",
    "compute.projects.get",
    "osconfig.patchJobs.exec",
    "osconfig.patchJobs.list",
    "osconfig.patchJobs.get",
    "storage.buckets.create",
    "storage.buckets.delete",
    "storage.objects.create",
    "storage.objects.delete",
    "storage.objects.get",
    "storage.objects.list",
    "compute.disks.get",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.getOpenIdToken",
    "pubsub.topics.publish",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.list",
    "compute.snapshots.delete",
    "compute.instances.setLabels",
    "compute.snapshots.create",
    "compute.snapshots.setLabels"
  ]
}

# All APIs that need to be enabled for Workload Identity Federation related on-boarding
variable "workload-identity-federation-apis" {
  type = list(string)
  default = [
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
  ]
}

locals {
  custom_non_compute_permissions = setunion(var.custom_role_permissions_monitor_proj, var.custom_role_permissions_protect_proj)
  custom_permissions_monitor_and_protect = var.is_compute_enabled == "true"? setunion(local.custom_non_compute_permissions, var.compute_role_permissions_proj) : local.custom_non_compute_permissions
  is_wif_selected = var.authentication_type == "external_account" ? true : false
}

variable "custom_role_flowlog_permissions_project" {
  type = list(string)
  default = [
    "storage.objects.get",
    "storage.objects.list"
  ]
}

#############################
# Initializing the provider
##############################
terraform {
  required_providers {
    google = "~> 3.90"
    google-beta = "~> 3.90"
    random = "~> 3.1"
  }
}
provider "google" {}
provider "random" {}

provider "google-beta" {
  project = var.project_id
}


##############################
# Creating the service account
##############################
resource "random_string" "unique_id" {
  length = 5
  min_lower = 5
  special = false
}

resource "google_service_account" "prisma_cloud_service_account" {
  account_id = "prisma-cloud-serv-${random_string.unique_id.result}"
  display_name = "Prisma Cloud Service Account"
  project = var.project_id
}

resource "google_service_account_key" "prisma_cloud_service_account_key" {
  count = local.is_wif_selected == true ? 0: 1
  service_account_id = google_service_account.prisma_cloud_service_account.name
}


##############################
# Creating custom role
# on PROJECT level
##############################
resource "google_project_iam_custom_role" "prisma_cloud_project_custom_role" {
  project = var.project_id
  role_id = "prismaCloudViewer${random_string.unique_id.result}"
  title = "Prisma Cloud Viewer ${random_string.unique_id.result}"
  description = "This is a custom role created for Prisma Cloud. Contains granular additional permission which is not covered by built-in roles"
  permissions = var.protection_mode_proj == "monitor_and_protect" ? local.custom_permissions_monitor_and_protect : var.custom_role_permissions_monitor_proj
}

resource "google_project_iam_custom_role" "prisma_cloud_custom_role_flowlog" {
  project = var.project_id
  count = var.flowlog_bucket_name_project != "" ? 1 : 0
  role_id = "prismaCloudFlowLogViewer${random_string.unique_id.result}"
  title = "Prisma Cloud Flow Logs Viewer ${random_string.unique_id.result}"
  description = "This is a custom role created for Prisma Cloud. Contains granular permission which is needed for flow logs"
  permissions = var.custom_role_flowlog_permissions_project
}

##############################
# Attaching role permissions
# to the service account
##############################
resource "google_project_iam_member" "bind_role_project-viewer" {
  project = var.project_id
  role = "roles/viewer"
  member = "serviceAccount:${google_service_account.prisma_cloud_service_account.email}"
}

resource "google_project_iam_member" "bind_role_compute-security-admin" {
  project = var.project_id
  count = var.protection_mode_proj == "monitor_and_protect" ? 1 : 0
  role = "roles/compute.securityAdmin"
  member = "serviceAccount:${google_service_account.prisma_cloud_service_account.email}"
}

resource "google_project_iam_member" "bind-role-prisma-cloud-viewer" {
  project = var.project_id
  role = "projects/${var.project_id}/roles/${google_project_iam_custom_role.prisma_cloud_project_custom_role.role_id}"
  member = "serviceAccount:${google_service_account.prisma_cloud_service_account.email}"
}

resource "google_storage_bucket_iam_binding" "binding" {
  count = var.flowlog_bucket_name_project != "" ? 1 : 0
  bucket = var.flowlog_bucket_name_project
  role = "projects/${var.project_id}/roles/${google_project_iam_custom_role.prisma_cloud_custom_role_flowlog[0].role_id}"
  members = [
    "serviceAccount:${google_service_account.prisma_cloud_service_account.email}"]
}

###################
# Enable Services
###################
resource "google_project_service" "enable_dns" {
  project = var.project_id
  service = "dns.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_bigquery" {
  project = var.project_id
  service = "bigquery.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_cloudkms" {
  project = var.project_id
  service = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_cloudresourcemanager" {
  project = var.project_id
  service = "cloudresourcemanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_monitoring" {
  project = var.project_id
  service = "monitoring.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_logging" {
  project = var.project_id
  service = "logging.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_container" {
  project = var.project_id
  service = "container.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_iam" {
  project = var.project_id
  service = "iam.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_storage_component" {
  project = var.project_id
  service = "storage-component.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_sql_component" {
  project = var.project_id
  service = "sql-component.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_service_compute" {
  project = var.project_id
  service = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_redis" {
  project = var.project_id
  service = "redis.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_cloudfunctions" {
  project = var.project_id
  service = "cloudfunctions.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_recommender" {
  project = var.project_id
  service = "recommender.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_dataproc" {
  project = var.project_id
  service = "dataproc.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_bigtableadmin" {
  project = var.project_id
  service = "bigtableadmin.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_serviceusage" {
  project = var.project_id
  service = "serviceusage.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_appengine" {
  project = var.project_id
  service = "appengine.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_run" {
  project = var.project_id
  service = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_pubsub" {
  project = var.project_id
  service = "pubsub.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_spanner" {
  project = var.project_id
  service = "spanner.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_sourcerepo" {
  project = var.project_id
  service = "sourcerepo.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_websecurityscanner" {
  project = var.project_id
  service = "websecurityscanner.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_binaryauth" {
  project = var.project_id
  service = "binaryauthorization.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_cloudtask" {
  project = var.project_id
  service = "cloudtasks.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_secretmanager" {
  project = var.project_id
  service = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_healthcare" {
  project = var.project_id
  service = "healthcare.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_filestore" {
  project = var.project_id
  service = "file.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_cloud_asset_inventory" {
  project = var.project_id
  service = "cloudasset.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_firebaserules" {
  project = var.project_id
  service = "firebaserules.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_composer" {
  project = var.project_id
  service = "composer.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_containeranalysis" {
  project = var.project_id
  service = "containeranalysis.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_ml" {
  project = var.project_id
  service = "ml.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_apigateway" {
  project = var.project_id
  service = "apigateway.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_datafusion" {
  project = var.project_id
  service = "datafusion.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_apikey" {
  project = var.project_id
  service = "apikeys.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_identityawareproxy" {
  project = var.project_id
  service = "iap.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_certificateauthorityservice" {
  project = var.project_id
  service = "privateca.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_accessapproval" {
  project = var.project_id
  service = "accessapproval.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_essentialcontacts" {
  project = var.project_id
  service = "essentialcontacts.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_servicedirectory" {
  project = var.project_id
  service = "servicedirectory.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_orgpolicy" {
  project = var.project_id
  service = "orgpolicy.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_managedidentities" {
  project = var.project_id
  service = "managedidentities.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_datacatalog" {
  project = var.project_id
  service = "datacatalog.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_securitycenter" {
  project = var.project_id
  service = "securitycenter.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_notebooks" {
  project = var.project_id
  service = "notebooks.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_artifactregistry" {
  project = var.project_id
  service = "artifactregistry.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_datastore" {
  project = var.project_id
  service = "datastore.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_networksecurity" {
  project = var.project_id
  service = "networksecurity.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_dlp" {
  project = var.project_id
  service = "dlp.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "enable_firebaseremoteconfig" {
  project = var.project_id
  service = "firebaseremoteconfig.googleapis.com"
  disable_on_destroy = false
}

# Enables all services given in the list to enable
module "project-services" {
  count = local.is_wif_selected == true ? 1: 0
  source  = "terraform-google-modules/project-factory/google//modules/project_services"
  version = "10.1.1"
  project_id = var.project_id

  activate_apis = var.workload-identity-federation-apis
  disable_services_on_destroy = false
}

resource "local_file" "key" {
  count = local.is_wif_selected == true ? 0: 1
  filename = "${var.project_id}-${random_string.unique_id.result}.json"
  content = base64decode(google_service_account_key.prisma_cloud_service_account_key[count.index].private_key)
}


###################
# WORKLOAD IDENTITY FEDERATION RELATED COMPONENTS - IF OPTED BY USER
###################


# Workload Identity Pool
resource "google_iam_workload_identity_pool" "prisma_workload_identity_pool" {
  count = local.is_wif_selected == true ? 1: 0
  provider                  = google-beta
  workload_identity_pool_id = "${var.global_identifier}-pool-${random_string.unique_id.result}"
  display_name              = var.global_identifier_friendly_name
  description               = "${var.global_identifier_friendly_name} Workload Identity Pool"
}


resource "google_iam_workload_identity_pool_provider" "prisma_workload_identity_pool_provider" {
  count = local.is_wif_selected == true ? 1: 0
  provider                           = google-beta
  workload_identity_pool_id          = google_iam_workload_identity_pool.prisma_workload_identity_pool[count.index].workload_identity_pool_id
  workload_identity_pool_provider_id = "${var.global_identifier}-aws-provider-${random_string.unique_id.result}"
  display_name                       = var.global_identifier_friendly_name
  aws {
    account_id = var.prisma_aws_account_id
  }
}

resource "google_service_account_iam_member" "prisma-federated-service-account-role-binding" {
  count = local.is_wif_selected == true ? 1: 0
  service_account_id = google_service_account.prisma_cloud_service_account.id
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.prisma_workload_identity_pool[count.index].name}/*"

  depends_on = [google_iam_workload_identity_pool.prisma_workload_identity_pool]
}

####################
## OUTPUT (And Next Steps to the User)
####################

output "user_instruction" {
  value = local.is_wif_selected == false ? "Successfully Configured !!\n\n What to do next ?\n\t1. Please download the file ${local_file.key[0].filename}\n\nUse the downloaded JSON file and Proceed at Prisma Cloud UI" : "Federated Access Configuration Successful !!\n\n What to do next ? \n\t1. Go to https://console.cloud.google.com/iam-admin/workload-identity-pools/pool/${google_iam_workload_identity_pool.prisma_workload_identity_pool[0].workload_identity_pool_id}?project=${var.project_id} \n\t2. Click on 'Connected Service Accounts'\n\t3. Click DOWNLOAD (Next to ${google_service_account.prisma_cloud_service_account.account_id})\n\t4. Select 'Prisma Cloud' as Provider and click 'Download Config'\n\nUse the downloaded JSON file and Proceed at Prisma Cloud UI"
}
