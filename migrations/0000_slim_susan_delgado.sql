CREATE TABLE "aev_evaluations" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"asset_id" varchar NOT NULL,
	"exposure_type" varchar NOT NULL,
	"priority" varchar DEFAULT 'medium' NOT NULL,
	"description" text NOT NULL,
	"adversary_profile" varchar,
	"execution_mode" varchar DEFAULT 'safe',
	"status" varchar DEFAULT 'pending' NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "aev_results" (
	"id" varchar PRIMARY KEY NOT NULL,
	"evaluation_id" varchar NOT NULL,
	"exploitable" boolean NOT NULL,
	"confidence" integer NOT NULL,
	"score" integer NOT NULL,
	"attack_path" jsonb,
	"attack_graph" jsonb,
	"business_logic_findings" jsonb,
	"multi_vector_findings" jsonb,
	"workflow_analysis" jsonb,
	"impact" text,
	"recommendations" jsonb,
	"evidence_artifacts" jsonb,
	"intelligent_score" jsonb,
	"remediation_guidance" jsonb,
	"llm_validation" jsonb,
	"llm_validation_verdict" varchar,
	"debate_summary" jsonb,
	"duration" integer,
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "agent_commands" (
	"id" varchar PRIMARY KEY NOT NULL,
	"agent_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"command_type" varchar NOT NULL,
	"payload" jsonb,
	"status" varchar DEFAULT 'pending',
	"created_at" timestamp DEFAULT now(),
	"acknowledged_at" timestamp,
	"executed_at" timestamp,
	"expires_at" timestamp,
	"result" jsonb,
	"error_message" text
);
--> statement-breakpoint
CREATE TABLE "agent_deployment_jobs" (
	"id" varchar PRIMARY KEY NOT NULL,
	"cloud_asset_id" varchar NOT NULL,
	"connection_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"deployment_method" varchar NOT NULL,
	"status" varchar DEFAULT 'pending',
	"deployment_command" text,
	"deployment_config" jsonb,
	"attempts" integer DEFAULT 0,
	"max_attempts" integer DEFAULT 3,
	"scheduled_at" timestamp,
	"started_at" timestamp,
	"completed_at" timestamp,
	"result_agent_id" varchar,
	"error_message" text,
	"error_details" jsonb,
	"initiated_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "agent_findings" (
	"id" varchar PRIMARY KEY NOT NULL,
	"agent_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"telemetry_id" varchar,
	"finding_type" varchar NOT NULL,
	"severity" varchar NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"affected_component" varchar,
	"affected_version" varchar,
	"affected_port" integer,
	"affected_service" varchar,
	"cve_id" varchar,
	"cvss_score" integer,
	"confidence_score" integer DEFAULT 0,
	"confidence_factors" jsonb,
	"verification_status" varchar DEFAULT 'unverified',
	"verified_by" varchar,
	"verified_at" timestamp,
	"verification_notes" text,
	"llm_validation" jsonb,
	"llm_validation_verdict" varchar,
	"recommendation" text,
	"status" varchar DEFAULT 'new',
	"assigned_to" varchar,
	"aev_evaluation_id" varchar,
	"auto_evaluation_triggered" boolean DEFAULT false,
	"detected_at" timestamp NOT NULL,
	"acknowledged_at" timestamp,
	"resolved_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "agent_registration_tokens" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"token_hash" varchar NOT NULL,
	"name" text,
	"description" text,
	"used_at" timestamp,
	"used_by_agent_id" varchar,
	"expires_at" timestamp NOT NULL,
	"created_by_user_id" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "agent_telemetry" (
	"id" varchar PRIMARY KEY NOT NULL,
	"agent_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"system_info" jsonb,
	"resource_metrics" jsonb,
	"services" jsonb,
	"open_ports" jsonb,
	"network_connections" jsonb,
	"installed_software" jsonb,
	"config_data" jsonb,
	"security_findings" jsonb,
	"raw_data" jsonb,
	"collected_at" timestamp NOT NULL,
	"received_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ai_adversary_profiles" (
	"id" varchar PRIMARY KEY NOT NULL,
	"name" varchar NOT NULL,
	"profile_type" varchar NOT NULL,
	"description" text,
	"capabilities" jsonb,
	"typical_ttps" jsonb,
	"motivations" jsonb,
	"target_preferences" jsonb,
	"avg_dwell_time" integer,
	"detection_difficulty" varchar,
	"is_built_in" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ai_simulations" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"attacker_profile_id" varchar,
	"defender_config" jsonb,
	"target_environment" jsonb,
	"simulation_status" varchar DEFAULT 'pending',
	"simulation_results" jsonb,
	"started_at" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "api_definitions" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"tenant_id" varchar DEFAULT 'default' NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"version" varchar(50),
	"spec_version" varchar(20),
	"base_url" varchar(500),
	"raw_spec" text,
	"servers" jsonb,
	"security_schemes" jsonb,
	"total_endpoints" integer DEFAULT 0,
	"total_operations" integer DEFAULT 0,
	"status" varchar DEFAULT 'active',
	"last_scanned_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	"created_by" varchar(255)
);
--> statement-breakpoint
CREATE TABLE "api_endpoints" (
	"id" varchar PRIMARY KEY NOT NULL,
	"api_definition_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"path" varchar(500) NOT NULL,
	"method" varchar(10) NOT NULL,
	"operation_id" varchar(255),
	"summary" text,
	"description" text,
	"tags" jsonb,
	"parameters" jsonb,
	"request_body" jsonb,
	"responses" jsonb,
	"security" jsonb,
	"vulnerability_potential" jsonb,
	"priority" varchar(20) DEFAULT 'medium',
	"last_scanned_at" timestamp,
	"scan_status" varchar DEFAULT 'pending',
	"findings_count" integer DEFAULT 0,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "api_scan_results" (
	"id" varchar PRIMARY KEY NOT NULL,
	"scan_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"organization_id" varchar NOT NULL,
	"base_url" varchar NOT NULL,
	"spec_url" varchar,
	"endpoints" jsonb DEFAULT '[]'::jsonb,
	"vulnerabilities" jsonb DEFAULT '[]'::jsonb,
	"ai_findings" jsonb DEFAULT '[]'::jsonb,
	"status" varchar DEFAULT 'pending',
	"scan_started" timestamp,
	"scan_completed" timestamp,
	"error_message" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "approval_requests" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"request_type" varchar NOT NULL,
	"requested_by" varchar NOT NULL,
	"requested_by_name" varchar,
	"required_level" varchar NOT NULL,
	"status" varchar DEFAULT 'pending' NOT NULL,
	"target_host" varchar,
	"target_scope" jsonb,
	"execution_mode" varchar,
	"operation_type" varchar,
	"justification" text NOT NULL,
	"risk_assessment" text,
	"estimated_impact" varchar,
	"duration_minutes" integer,
	"approved_by" varchar,
	"approved_by_name" varchar,
	"approval_notes" text,
	"denial_reason" text,
	"expires_at" timestamp,
	"approved_at" timestamp,
	"denied_at" timestamp,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "attack_paths" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"tenant_id" varchar DEFAULT 'default' NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"entry_point" varchar(255) NOT NULL,
	"target_objective" varchar(255),
	"path_nodes" jsonb,
	"path_edges" jsonb,
	"total_hops" integer,
	"overall_risk" varchar DEFAULT 'medium',
	"exploitability" integer,
	"mitre_techniques" jsonb,
	"kill_chain_phases" jsonb,
	"status" varchar DEFAULT 'discovered',
	"last_validated_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "attack_predictions" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"asset_id" varchar,
	"prediction_date" timestamp DEFAULT now(),
	"time_horizon" varchar NOT NULL,
	"predicted_attack_vectors" jsonb,
	"overall_breach_likelihood" integer,
	"risk_factors" jsonb,
	"recommended_actions" jsonb,
	"model_version" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" varchar PRIMARY KEY NOT NULL,
	"execution_id" varchar NOT NULL,
	"evaluation_id" varchar NOT NULL,
	"organization_id" varchar NOT NULL,
	"agent_name" varchar NOT NULL,
	"log_type" varchar NOT NULL,
	"content" text,
	"prompt" text,
	"response" text,
	"command_input" text,
	"command_output" text,
	"decision" varchar,
	"decision_reason" text,
	"object_storage_key" varchar,
	"object_storage_type" varchar,
	"object_storage_size" integer,
	"metadata" jsonb,
	"parent_log_id" varchar,
	"sequence_number" integer NOT NULL,
	"duration_ms" integer,
	"model_used" varchar,
	"token_count" integer,
	"checksum" varchar,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "auth_scan_results" (
	"id" varchar PRIMARY KEY NOT NULL,
	"scan_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"organization_id" varchar NOT NULL,
	"target_url" varchar NOT NULL,
	"auth_type" varchar NOT NULL,
	"test_results" jsonb DEFAULT '[]'::jsonb,
	"vulnerabilities" jsonb DEFAULT '[]'::jsonb,
	"overall_score" integer,
	"status" varchar DEFAULT 'pending',
	"scan_started" timestamp,
	"scan_completed" timestamp,
	"error_message" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "authorization_logs" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"user_id" varchar,
	"user_name" varchar,
	"action" varchar NOT NULL,
	"target_asset" varchar,
	"evaluation_id" varchar,
	"execution_mode" varchar,
	"details" jsonb,
	"ip_address" varchar,
	"user_agent" varchar,
	"authorized" boolean DEFAULT true,
	"authorization_reason" text,
	"risk_level" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "auto_deploy_configs" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" varchar(255) NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"providers" jsonb DEFAULT '["aws","azure","gcp"]'::jsonb,
	"asset_types" jsonb DEFAULT '["ec2","vm","gce"]'::jsonb,
	"target_platforms" jsonb DEFAULT '["linux","windows"]'::jsonb,
	"deployment_options" jsonb DEFAULT '{"maxConcurrentDeployments":10,"deploymentTimeoutSeconds":300,"retryFailedDeployments":true,"maxRetries":3,"skipOfflineAssets":true}'::jsonb,
	"filter_rules" jsonb,
	"total_deployments_triggered" integer DEFAULT 0,
	"last_deployment_triggered_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	"created_by" varchar(255)
);
--> statement-breakpoint
CREATE TABLE "cloud_assets" (
	"id" varchar PRIMARY KEY NOT NULL,
	"connection_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"provider_resource_id" varchar NOT NULL,
	"provider" varchar NOT NULL,
	"asset_type" varchar NOT NULL,
	"asset_name" text NOT NULL,
	"region" varchar,
	"availability_zone" varchar,
	"instance_type" varchar,
	"cpu_count" integer,
	"memory_mb" integer,
	"public_ip_addresses" jsonb,
	"private_ip_addresses" jsonb,
	"power_state" varchar,
	"health_status" varchar,
	"agent_installed" boolean DEFAULT false,
	"agent_id" varchar,
	"agent_deployable" boolean DEFAULT true,
	"agent_deployment_method" varchar,
	"last_agent_deployment_attempt" timestamp,
	"agent_deployment_status" varchar,
	"agent_deployment_error" text,
	"provider_tags" jsonb,
	"raw_metadata" jsonb,
	"first_discovered_at" timestamp DEFAULT now(),
	"last_seen_at" timestamp DEFAULT now(),
	"discovery_job_id" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cloud_connections" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"name" text NOT NULL,
	"provider" varchar NOT NULL,
	"aws_access_key_id" varchar,
	"aws_regions" jsonb,
	"aws_assume_role_arn" varchar,
	"azure_tenant_id" varchar,
	"azure_client_id" varchar,
	"azure_subscription_ids" jsonb,
	"gcp_project_ids" jsonb,
	"gcp_service_account_email" varchar,
	"status" varchar DEFAULT 'pending',
	"last_sync_at" timestamp,
	"last_sync_status" varchar,
	"last_error" text,
	"sync_enabled" boolean DEFAULT true,
	"sync_interval" integer DEFAULT 3600,
	"assets_discovered" integer DEFAULT 0,
	"last_asset_count" integer DEFAULT 0,
	"iam_findings" jsonb,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cloud_credentials" (
	"id" varchar PRIMARY KEY NOT NULL,
	"connection_id" varchar NOT NULL,
	"encrypted_data" text NOT NULL,
	"encryption_key_id" varchar NOT NULL,
	"credential_type" varchar NOT NULL,
	"last_rotated_at" timestamp,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "cloud_discovery_jobs" (
	"id" varchar PRIMARY KEY NOT NULL,
	"connection_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"status" varchar DEFAULT 'pending',
	"job_type" varchar DEFAULT 'full',
	"total_regions" integer DEFAULT 0,
	"completed_regions" integer DEFAULT 0,
	"total_assets" integer DEFAULT 0,
	"new_assets" integer DEFAULT 0,
	"updated_assets" integer DEFAULT 0,
	"removed_assets" integer DEFAULT 0,
	"started_at" timestamp,
	"completed_at" timestamp,
	"estimated_duration" integer,
	"errors" jsonb,
	"triggered_by" varchar,
	"trigger_type" varchar DEFAULT 'manual',
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "conversations" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "conversations_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"title" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "defensive_posture_scores" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"calculated_at" timestamp DEFAULT now(),
	"overall_score" integer NOT NULL,
	"category_scores" jsonb,
	"breach_likelihood" integer,
	"mean_time_to_detect" integer,
	"mean_time_to_respond" integer,
	"vulnerability_exposure" jsonb,
	"trend_direction" varchar,
	"benchmark_percentile" integer,
	"recommendations" jsonb
);
--> statement-breakpoint
CREATE TABLE "defensive_validations" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"evaluation_id" varchar NOT NULL,
	"siem_connection_id" varchar NOT NULL,
	"attack_started_at" timestamp,
	"attack_completed_at" timestamp,
	"mitre_attack_id" varchar,
	"mitre_tactic" varchar,
	"detected" boolean DEFAULT false,
	"first_alert_at" timestamp,
	"alert_count" integer DEFAULT 0,
	"alert_ids" jsonb,
	"alert_details" jsonb,
	"mttd_seconds" integer,
	"mttr_seconds" integer,
	"resolved_at" timestamp,
	"status" varchar DEFAULT 'pending',
	"error_message" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "discovered_assets" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"asset_identifier" varchar NOT NULL,
	"display_name" text,
	"asset_type" varchar NOT NULL,
	"status" varchar DEFAULT 'active',
	"ip_addresses" jsonb,
	"hostname" varchar,
	"fqdn" varchar,
	"mac_address" varchar,
	"cloud_provider" varchar,
	"cloud_region" varchar,
	"cloud_account_id" varchar,
	"cloud_resource_id" varchar,
	"cloud_tags" jsonb,
	"operating_system" varchar,
	"os_version" varchar,
	"installed_software" jsonb,
	"open_ports" jsonb,
	"business_unit" varchar,
	"owner" varchar,
	"criticality" varchar DEFAULT 'medium',
	"environment" varchar,
	"last_seen" timestamp,
	"first_discovered" timestamp DEFAULT now(),
	"discovery_source" varchar,
	"import_job_id" varchar,
	"last_evaluated_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "discovered_credentials" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"tenant_id" varchar DEFAULT 'default' NOT NULL,
	"source_type" varchar NOT NULL,
	"source_id" varchar,
	"source_host" varchar(255),
	"credential_type" varchar NOT NULL,
	"username" varchar(255),
	"domain" varchar(255),
	"credential_value" text,
	"credential_hash" varchar(128),
	"validated_on" jsonb,
	"potential_targets" jsonb,
	"usable_for_techniques" jsonb,
	"privilege_level" varchar DEFAULT 'user',
	"risk_score" integer,
	"is_active" boolean DEFAULT true,
	"last_validated_at" timestamp,
	"expires_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "endpoint_agents" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"agent_name" text NOT NULL,
	"api_key" varchar NOT NULL,
	"api_key_hash" varchar,
	"hostname" varchar,
	"platform" varchar,
	"platform_version" varchar,
	"architecture" varchar,
	"ip_addresses" jsonb,
	"mac_addresses" jsonb,
	"agent_version" varchar,
	"capabilities" jsonb,
	"status" varchar DEFAULT 'offline',
	"last_heartbeat" timestamp,
	"last_telemetry" timestamp,
	"telemetry_interval" integer DEFAULT 300,
	"scan_enabled" boolean DEFAULT true,
	"config_audit_enabled" boolean DEFAULT true,
	"tags" jsonb,
	"environment" varchar,
	"registered_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "endpoint_agents_api_key_unique" UNIQUE("api_key")
);
--> statement-breakpoint
CREATE TABLE "enrollment_tokens" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"token_hash" varchar NOT NULL,
	"token_hint" varchar NOT NULL,
	"expires_at" timestamp NOT NULL,
	"revoked" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "evaluation_history" (
	"id" varchar PRIMARY KEY NOT NULL,
	"asset_id" varchar NOT NULL,
	"evaluation_id" varchar NOT NULL,
	"batch_job_id" varchar,
	"scheduled_scan_id" varchar,
	"snapshot" jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "exploit_validation_results" (
	"id" varchar PRIMARY KEY NOT NULL,
	"validation_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"organization_id" varchar NOT NULL,
	"finding_id" varchar NOT NULL,
	"evaluation_id" varchar,
	"exploit_type" varchar NOT NULL,
	"safe_mode" boolean DEFAULT true,
	"verdict" varchar,
	"exploitable" boolean,
	"confidence" integer,
	"validation_stats" jsonb,
	"evidence" jsonb DEFAULT '[]'::jsonb,
	"attack_path" jsonb,
	"status" varchar DEFAULT 'pending',
	"validation_started" timestamp,
	"validation_completed" timestamp,
	"error_message" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "forensic_exports" (
	"id" varchar PRIMARY KEY NOT NULL,
	"evaluation_id" varchar NOT NULL,
	"execution_id" varchar NOT NULL,
	"organization_id" varchar NOT NULL,
	"exported_by" varchar NOT NULL,
	"encryption_key_hash" varchar NOT NULL,
	"object_storage_key" varchar NOT NULL,
	"file_size" integer NOT NULL,
	"log_count" integer NOT NULL,
	"includes_screenshots" boolean DEFAULT false,
	"includes_network_captures" boolean DEFAULT false,
	"expires_at" timestamp,
	"download_count" integer DEFAULT 0,
	"metadata" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "full_assessments" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"name" varchar NOT NULL,
	"description" text,
	"assessment_mode" varchar DEFAULT 'agent' NOT NULL,
	"target_url" varchar,
	"agent_ids" jsonb,
	"finding_ids" jsonb,
	"status" varchar DEFAULT 'pending' NOT NULL,
	"progress" integer DEFAULT 0 NOT NULL,
	"current_phase" varchar,
	"overall_risk_score" integer,
	"critical_path_count" integer,
	"systems_analyzed" integer,
	"findings_analyzed" integer,
	"unified_attack_graph" jsonb,
	"executive_summary" text,
	"recon_findings" jsonb,
	"vulnerability_findings" jsonb,
	"lateral_movement_paths" jsonb,
	"business_impact_analysis" jsonb,
	"web_app_recon" jsonb,
	"validated_findings" jsonb,
	"agent_dispatch_stats" jsonb,
	"recommendations" jsonb,
	"started_at" timestamp,
	"completed_at" timestamp,
	"duration_ms" integer,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "hitl_approval_requests" (
	"id" varchar PRIMARY KEY NOT NULL,
	"evaluation_id" varchar NOT NULL,
	"execution_id" varchar NOT NULL,
	"organization_id" varchar NOT NULL,
	"agent_name" varchar NOT NULL,
	"command" text NOT NULL,
	"target" varchar,
	"risk_level" varchar NOT NULL,
	"risk_reason" text NOT NULL,
	"matched_policies" jsonb,
	"status" varchar DEFAULT 'pending' NOT NULL,
	"requested_at" timestamp DEFAULT now() NOT NULL,
	"expires_at" timestamp NOT NULL,
	"responded_at" timestamp,
	"responded_by" varchar,
	"response_signature" varchar,
	"response_nonce" varchar,
	"rejection_reason" text,
	"metadata" jsonb
);
--> statement-breakpoint
CREATE TABLE "import_jobs" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"source_type" varchar NOT NULL,
	"file_name" varchar,
	"file_size" integer,
	"file_mime_type" varchar,
	"status" varchar DEFAULT 'pending',
	"progress" integer DEFAULT 0,
	"total_records" integer DEFAULT 0,
	"processed_records" integer DEFAULT 0,
	"successful_records" integer DEFAULT 0,
	"failed_records" integer DEFAULT 0,
	"skipped_records" integer DEFAULT 0,
	"assets_discovered" integer DEFAULT 0,
	"vulnerabilities_found" integer DEFAULT 0,
	"errors" jsonb,
	"started_at" timestamp,
	"completed_at" timestamp,
	"initiated_by" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "lateral_movement_findings" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"tenant_id" varchar DEFAULT 'default' NOT NULL,
	"sandbox_session_id" varchar,
	"technique" varchar NOT NULL,
	"source_host" varchar(255) NOT NULL,
	"target_host" varchar(255) NOT NULL,
	"credential_id" varchar,
	"credential_type" varchar,
	"success" boolean NOT NULL,
	"access_level" varchar,
	"evidence" jsonb,
	"mitre_attack_id" varchar(20),
	"mitre_tactic" varchar(50),
	"severity" varchar DEFAULT 'medium',
	"business_impact" text,
	"recommendations" jsonb,
	"execution_time_ms" integer,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "live_scan_results" (
	"id" varchar PRIMARY KEY NOT NULL,
	"evaluation_id" varchar NOT NULL,
	"organization_id" varchar NOT NULL,
	"target_host" varchar NOT NULL,
	"resolved_ip" varchar,
	"resolved_hostname" varchar,
	"ports" jsonb,
	"vulnerabilities" jsonb,
	"scan_started" timestamp,
	"scan_completed" timestamp,
	"status" varchar DEFAULT 'pending',
	"error_message" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "messages" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "messages_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"conversation_id" integer NOT NULL,
	"role" text NOT NULL,
	"content" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "metrics_history" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"metric_type" varchar NOT NULL,
	"mitre_attack_id" varchar,
	"asset_id" varchar,
	"value_seconds" integer,
	"value_percent" integer,
	"sample_size" integer DEFAULT 0,
	"period_start" timestamp,
	"period_end" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "organization_governance" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"execution_mode" varchar DEFAULT 'safe' NOT NULL,
	"kill_switch_active" boolean DEFAULT false,
	"kill_switch_activated_at" timestamp,
	"kill_switch_activated_by" varchar,
	"rate_limit_per_hour" integer DEFAULT 100,
	"rate_limit_per_day" integer DEFAULT 1000,
	"concurrent_evaluations_limit" integer DEFAULT 5,
	"current_concurrent_evaluations" integer DEFAULT 0,
	"allowed_target_patterns" jsonb DEFAULT '[]'::jsonb,
	"blocked_target_patterns" jsonb DEFAULT '[]'::jsonb,
	"allowed_network_ranges" jsonb DEFAULT '[]'::jsonb,
	"require_authorization_for_live" boolean DEFAULT true,
	"auto_kill_on_critical" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "organization_governance_organization_id_unique" UNIQUE("organization_id")
);
--> statement-breakpoint
CREATE TABLE "pivot_points" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"tenant_id" varchar DEFAULT 'default' NOT NULL,
	"hostname" varchar(255) NOT NULL,
	"ip_address" varchar(45),
	"network_segment" varchar(50),
	"access_method" varchar,
	"access_credential_id" varchar,
	"access_level" varchar DEFAULT 'user',
	"reachable_from" jsonb,
	"reachable_to" jsonb,
	"pivot_score" integer,
	"strategic_value" text,
	"discovered_services" jsonb,
	"is_active" boolean DEFAULT true,
	"last_verified_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "purple_team_findings" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"evaluation_id" varchar,
	"finding_type" varchar NOT NULL,
	"offensive_technique" varchar,
	"offensive_description" text,
	"detection_status" varchar,
	"existing_control" text,
	"control_effectiveness" integer,
	"defensive_recommendation" text,
	"implementation_priority" varchar,
	"estimated_effort" varchar,
	"feedback_status" varchar DEFAULT 'pending',
	"assigned_to" varchar,
	"resolved_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "rate_limit_tracking" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"window_start" timestamp NOT NULL,
	"window_type" varchar NOT NULL,
	"request_count" integer DEFAULT 0,
	"evaluation_count" integer DEFAULT 0,
	"blocked_count" integer DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE "recon_scans" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"target" varchar NOT NULL,
	"status" varchar DEFAULT 'pending' NOT NULL,
	"scan_time" timestamp DEFAULT now(),
	"port_scan" jsonb,
	"ssl_check" jsonb,
	"http_fingerprint" jsonb,
	"dns_enum" jsonb,
	"network_exposure" jsonb,
	"transport_security" jsonb,
	"application_identity" jsonb,
	"authentication_surface" jsonb,
	"infrastructure" jsonb,
	"attack_readiness" jsonb,
	"errors" jsonb DEFAULT '[]'::jsonb,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "remediation_results" (
	"id" varchar PRIMARY KEY NOT NULL,
	"remediation_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"organization_id" varchar NOT NULL,
	"evaluation_id" varchar,
	"finding_ids" jsonb DEFAULT '[]'::jsonb,
	"dry_run" boolean DEFAULT true,
	"actions" jsonb DEFAULT '[]'::jsonb,
	"guidance" jsonb,
	"summary" jsonb,
	"status" varchar DEFAULT 'pending',
	"remediation_started" timestamp,
	"remediation_completed" timestamp,
	"error_message" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "report_narratives" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"evaluation_id" varchar,
	"report_scope_id" varchar,
	"report_version" varchar DEFAULT 'v2_narrative' NOT NULL,
	"eno_json" jsonb,
	"model_meta" jsonb,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "reports" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"report_type" varchar NOT NULL,
	"report_version" varchar DEFAULT 'v1_template' NOT NULL,
	"title" text NOT NULL,
	"date_range_from" timestamp NOT NULL,
	"date_range_to" timestamp NOT NULL,
	"framework" varchar,
	"status" varchar DEFAULT 'generating' NOT NULL,
	"content" jsonb,
	"evaluation_ids" jsonb,
	"engagement_metadata" jsonb,
	"attestation" jsonb,
	"attack_narrative" jsonb,
	"generated_by" varchar,
	"created_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "safety_decisions" (
	"id" varchar PRIMARY KEY NOT NULL,
	"evaluation_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"agent_name" varchar NOT NULL,
	"original_action" text NOT NULL,
	"decision" varchar NOT NULL,
	"modified_action" text,
	"reasoning" text NOT NULL,
	"policy_references" jsonb DEFAULT '[]'::jsonb,
	"execution_mode" varchar DEFAULT 'safe',
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sandbox_executions" (
	"id" varchar PRIMARY KEY NOT NULL,
	"session_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"execution_type" varchar NOT NULL,
	"payload_name" varchar(255),
	"payload_category" varchar(100),
	"target_endpoint" varchar(500),
	"target_method" varchar(10),
	"payload_content" text,
	"payload_encoding" varchar(50),
	"status" varchar DEFAULT 'pending' NOT NULL,
	"success" boolean,
	"evidence" jsonb,
	"mitre_attack_id" varchar(20),
	"mitre_tactic" varchar(50),
	"execution_time_ms" integer,
	"started_at" timestamp,
	"completed_at" timestamp,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sandbox_sessions" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"tenant_id" varchar DEFAULT 'default' NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"target_url" varchar(500),
	"target_host" varchar(255),
	"execution_mode" varchar DEFAULT 'safe' NOT NULL,
	"status" varchar DEFAULT 'initializing' NOT NULL,
	"initial_state_snapshot" jsonb,
	"current_state_snapshot" jsonb,
	"resource_limits" jsonb,
	"total_executions" integer DEFAULT 0,
	"successful_executions" integer DEFAULT 0,
	"failed_executions" integer DEFAULT 0,
	"approved_by" varchar(255),
	"approved_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "sandbox_snapshots" (
	"id" varchar PRIMARY KEY NOT NULL,
	"session_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"snapshot_type" varchar DEFAULT 'manual' NOT NULL,
	"state_data" jsonb,
	"size_bytes" integer,
	"is_restorable" boolean DEFAULT true,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "scheduled_scans" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"assets" jsonb NOT NULL,
	"frequency" varchar NOT NULL,
	"day_of_week" integer,
	"day_of_month" integer,
	"time_of_day" varchar,
	"enabled" boolean DEFAULT true,
	"last_run_at" timestamp,
	"next_run_at" timestamp,
	"scan_type" varchar DEFAULT 'standard',
	"technique_set" jsonb,
	"trigger_condition" varchar,
	"source_evaluation_id" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "scope_rules" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"rule_type" varchar NOT NULL,
	"target_type" varchar NOT NULL,
	"target_value" text NOT NULL,
	"priority" integer DEFAULT 0,
	"enabled" boolean DEFAULT true,
	"expires_at" timestamp,
	"created_by" varchar,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "security_policies" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "security_policies_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"content" text NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb,
	"embedding" vector(1536),
	"organization_id" varchar(255),
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "siem_connections" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"name" text NOT NULL,
	"provider" varchar NOT NULL,
	"api_endpoint" text NOT NULL,
	"api_port" integer,
	"status" varchar DEFAULT 'pending',
	"last_sync_at" timestamp,
	"last_error" text,
	"elastic_index" varchar,
	"elastic_api_key" text,
	"elastic_cloud_id" text,
	"splunk_token" text,
	"splunk_index" varchar,
	"sentinel_workspace_id" varchar,
	"sentinel_tenant_id" varchar,
	"sentinel_client_id" varchar,
	"sentinel_client_secret" text,
	"sync_enabled" boolean DEFAULT true,
	"alert_query_window" integer DEFAULT 300,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ssh_credentials" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"asset_id" varchar,
	"connection_id" varchar,
	"host" varchar,
	"port" integer DEFAULT 22,
	"username" varchar NOT NULL,
	"auth_method" varchar DEFAULT 'key' NOT NULL,
	"encrypted_private_key" text,
	"encrypted_password" text,
	"encryption_key_id" varchar NOT NULL,
	"key_fingerprint" varchar,
	"use_sudo" boolean DEFAULT true,
	"sudo_password" boolean DEFAULT false,
	"status" varchar DEFAULT 'active',
	"last_used_at" timestamp,
	"last_validated_at" timestamp,
	"validation_error" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "tenants" (
	"id" varchar PRIMARY KEY NOT NULL,
	"name" varchar NOT NULL,
	"slug" varchar NOT NULL,
	"status" varchar DEFAULT 'active' NOT NULL,
	"tier" varchar DEFAULT 'starter' NOT NULL,
	"trial_ends_at" timestamp,
	"max_users" integer DEFAULT 5,
	"max_agents" integer DEFAULT 10,
	"max_evaluations_per_day" integer DEFAULT 100,
	"max_concurrent_scans" integer DEFAULT 3,
	"features" jsonb DEFAULT '{}'::jsonb,
	"allowed_ip_ranges" jsonb DEFAULT '[]'::jsonb,
	"enforce_ip_allowlist" boolean DEFAULT false,
	"billing_email" varchar,
	"technical_contact" varchar,
	"industry" varchar,
	"parent_tenant_id" varchar,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	"deleted_at" timestamp,
	CONSTRAINT "tenants_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "threat_intel_feeds" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"name" text NOT NULL,
	"feed_type" varchar NOT NULL,
	"feed_url" text NOT NULL,
	"enabled" boolean DEFAULT true,
	"check_interval" integer DEFAULT 86400,
	"last_checked_at" timestamp,
	"last_success_at" timestamp,
	"last_error" text,
	"indicator_count" integer DEFAULT 0,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "threat_intel_indicators" (
	"id" varchar PRIMARY KEY NOT NULL,
	"feed_id" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"indicator_type" varchar NOT NULL,
	"indicator_value" varchar NOT NULL,
	"vendor_project" varchar,
	"product" varchar,
	"vulnerability_name" text,
	"short_description" text,
	"required_action" text,
	"due_date" timestamp,
	"known_ransomware_campaign_use" boolean DEFAULT false,
	"matched_asset_count" integer DEFAULT 0,
	"matched_finding_ids" jsonb,
	"date_added" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ui_refresh_tokens" (
	"id" varchar PRIMARY KEY NOT NULL,
	"user_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"token_hash" varchar NOT NULL,
	"token_version" integer NOT NULL,
	"user_agent" varchar,
	"ip_address" varchar,
	"session_id" varchar,
	"expires_at" timestamp NOT NULL,
	"revoked_at" timestamp,
	"revoked_reason" varchar,
	"created_at" timestamp DEFAULT now(),
	"last_used_at" timestamp
);
--> statement-breakpoint
CREATE TABLE "ui_roles" (
	"id" varchar PRIMARY KEY NOT NULL,
	"name" varchar NOT NULL,
	"description" text,
	"can_manage_users" boolean DEFAULT false NOT NULL,
	"can_manage_roles" boolean DEFAULT false NOT NULL,
	"can_manage_settings" boolean DEFAULT false NOT NULL,
	"can_manage_agents" boolean DEFAULT false NOT NULL,
	"can_create_evaluations" boolean DEFAULT false NOT NULL,
	"can_run_simulations" boolean DEFAULT false NOT NULL,
	"can_view_evaluations" boolean DEFAULT true NOT NULL,
	"can_view_reports" boolean DEFAULT true NOT NULL,
	"can_export_data" boolean DEFAULT false NOT NULL,
	"can_access_audit_logs" boolean DEFAULT false NOT NULL,
	"can_manage_compliance" boolean DEFAULT false NOT NULL,
	"can_use_kill_switch" boolean DEFAULT false NOT NULL,
	"is_system_role" boolean DEFAULT false NOT NULL,
	"hierarchy_level" integer DEFAULT 100 NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ui_users" (
	"id" varchar PRIMARY KEY NOT NULL,
	"tenant_id" varchar DEFAULT 'default' NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"email" varchar NOT NULL,
	"password_hash" varchar NOT NULL,
	"display_name" varchar,
	"role_id" varchar DEFAULT 'executive_viewer' NOT NULL,
	"status" varchar DEFAULT 'active' NOT NULL,
	"token_version" integer DEFAULT 0 NOT NULL,
	"failed_login_attempts" integer DEFAULT 0 NOT NULL,
	"locked_until" timestamp,
	"last_login_at" timestamp,
	"last_activity_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"username" text NOT NULL,
	"password" text NOT NULL,
	"role" varchar DEFAULT 'viewer' NOT NULL,
	"display_name" text,
	"email" text,
	"created_at" timestamp DEFAULT now(),
	"last_login_at" timestamp,
	CONSTRAINT "users_username_unique" UNIQUE("username")
);
--> statement-breakpoint
CREATE TABLE "validation_audit_logs" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar NOT NULL,
	"tenant_id" varchar NOT NULL,
	"evaluation_id" varchar,
	"agent_id" varchar,
	"action" varchar NOT NULL,
	"execution_mode" varchar NOT NULL,
	"target_host" varchar,
	"target_port" integer,
	"probe_type" varchar,
	"vulnerability_type" varchar,
	"payload_used" text,
	"payload_hash" varchar,
	"result_status" varchar,
	"confidence_score" integer,
	"verdict" varchar,
	"evidence" text,
	"evidence_hash" varchar,
	"requested_by" varchar,
	"approved_by" varchar,
	"approval_id" varchar,
	"ip_address" varchar,
	"user_agent" varchar,
	"risk_level" varchar,
	"execution_duration_ms" integer,
	"metadata" jsonb,
	"checksum" varchar,
	"previous_record_hash" varchar,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "validation_evidence_artifacts" (
	"id" varchar PRIMARY KEY NOT NULL,
	"tenant_id" varchar NOT NULL,
	"organization_id" varchar NOT NULL,
	"evaluation_id" varchar,
	"finding_id" varchar,
	"validation_id" varchar,
	"scan_id" varchar,
	"evidence_type" varchar NOT NULL,
	"verdict" varchar DEFAULT 'theoretical' NOT NULL,
	"confidence_score" integer,
	"vulnerability_type" varchar,
	"target_url" varchar,
	"target_host" varchar,
	"target_port" integer,
	"http_request" jsonb,
	"http_response" jsonb,
	"timing_data" jsonb,
	"payload_used" text,
	"payload_type" varchar,
	"observed_behavior" text,
	"expected_behavior" text,
	"differential_analysis" text,
	"callback_received" boolean DEFAULT false,
	"callback_details" jsonb,
	"screenshot_url" varchar,
	"raw_data_base64" text,
	"validation_method" varchar,
	"execution_mode" varchar,
	"artifact_size_bytes" integer,
	"captured_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "vulnerability_imports" (
	"id" varchar PRIMARY KEY NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"import_job_id" varchar NOT NULL,
	"asset_id" varchar,
	"title" text NOT NULL,
	"description" text,
	"severity" varchar NOT NULL,
	"cve_id" varchar,
	"cvss_score" integer,
	"cvss_vector" varchar,
	"scanner_plugin_id" varchar,
	"scanner_name" varchar,
	"scanner_severity" varchar,
	"affected_host" varchar,
	"affected_port" integer,
	"affected_service" varchar,
	"affected_software" varchar,
	"affected_version" varchar,
	"solution" text,
	"solution_type" varchar,
	"patch_available" boolean,
	"exploit_available" boolean,
	"references" jsonb,
	"status" varchar DEFAULT 'open',
	"assigned_to" varchar,
	"due_date" timestamp,
	"aev_evaluation_id" varchar,
	"raw_data" jsonb,
	"detected_at" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "web_app_recon_scans" (
	"id" varchar PRIMARY KEY NOT NULL,
	"target_url" varchar NOT NULL,
	"organization_id" varchar DEFAULT 'default' NOT NULL,
	"tenant_id" varchar DEFAULT 'default' NOT NULL,
	"enable_parallel_agents" boolean DEFAULT true,
	"max_concurrent_agents" integer DEFAULT 5,
	"vulnerability_types" jsonb,
	"enable_llm_validation" boolean DEFAULT true,
	"status" varchar DEFAULT 'pending' NOT NULL,
	"progress" integer DEFAULT 0,
	"current_phase" varchar,
	"recon_result" jsonb,
	"agent_dispatch_result" jsonb,
	"validated_findings" jsonb,
	"created_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);
--> statement-breakpoint
ALTER TABLE "agent_deployment_jobs" ADD CONSTRAINT "agent_deployment_jobs_cloud_asset_id_cloud_assets_id_fk" FOREIGN KEY ("cloud_asset_id") REFERENCES "public"."cloud_assets"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_deployment_jobs" ADD CONSTRAINT "agent_deployment_jobs_connection_id_cloud_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."cloud_connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_endpoints" ADD CONSTRAINT "api_endpoints_api_definition_id_api_definitions_id_fk" FOREIGN KEY ("api_definition_id") REFERENCES "public"."api_definitions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_assets" ADD CONSTRAINT "cloud_assets_connection_id_cloud_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."cloud_connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_credentials" ADD CONSTRAINT "cloud_credentials_connection_id_cloud_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."cloud_connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_discovery_jobs" ADD CONSTRAINT "cloud_discovery_jobs_connection_id_cloud_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."cloud_connections"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "lateral_movement_findings" ADD CONSTRAINT "lateral_movement_findings_sandbox_session_id_sandbox_sessions_id_fk" FOREIGN KEY ("sandbox_session_id") REFERENCES "public"."sandbox_sessions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "lateral_movement_findings" ADD CONSTRAINT "lateral_movement_findings_credential_id_discovered_credentials_id_fk" FOREIGN KEY ("credential_id") REFERENCES "public"."discovered_credentials"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pivot_points" ADD CONSTRAINT "pivot_points_access_credential_id_discovered_credentials_id_fk" FOREIGN KEY ("access_credential_id") REFERENCES "public"."discovered_credentials"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sandbox_executions" ADD CONSTRAINT "sandbox_executions_session_id_sandbox_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sandbox_sessions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sandbox_snapshots" ADD CONSTRAINT "sandbox_snapshots_session_id_sandbox_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sandbox_sessions"("id") ON DELETE no action ON UPDATE no action;