//! Integration tests for Terraform resource binding.
//!
//! Each fixture is a directory under `tests/resources/terraform/` containing:
//! - `.tf` files (Terraform configuration)
//! - `app.py` (Python source with SDK calls)
//! - `expected_policies.json` (expected individual-policy output)
//! - `expected_merged_policy.json` (expected merged-policy output)
//! - Optionally `terraform.tfstate`, `variables.tf`, `terraform.tfvars`, `*.auto.tfvars`
//!
//! Three test modes exercise different code paths:
//! 1. **individual** — `--terraform-dir` + `individual_policies=true`
//! 2. **merged** — `--terraform-dir` + `individual_policies=false`
//! 3. **files** — `--terraform-file` + `--tfvars` + `--tfstate` (no dir)

use std::path::{Path, PathBuf};

use rstest::rstest;

use iam_policy_autopilot_policy_generation::api::generate_policies;
use iam_policy_autopilot_policy_generation::api::model::{
    AwsContext, ExtractSdkCallsConfig, GeneratePolicyConfig,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/resources/terraform")
}

fn fixture_path(name: &str, file: &str) -> PathBuf {
    fixtures_dir().join(name).join(file)
}

fn aws_context() -> AwsContext {
    AwsContext::new("us-east-1".into(), "123456789012".into()).unwrap()
}

/// Normalize a JSON value for deterministic comparison.
///
/// - Drops `Sid` keys (non-deterministic dedup counters)
/// - Sorts arrays by serialized form (non-deterministic HashMap iteration)
fn normalize(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let m: serde_json::Map<_, _> = map
                .iter()
                .filter(|(k, _)| k.as_str() != "Sid")
                .map(|(k, v)| (k.clone(), normalize(v)))
                .collect();
            serde_json::Value::Object(m)
        }
        serde_json::Value::Array(arr) => {
            let mut v: Vec<_> = arr.iter().map(normalize).collect();
            v.sort_by(|a, b| {
                serde_json::to_string(a)
                    .unwrap_or_default()
                    .cmp(&serde_json::to_string(b).unwrap_or_default())
            });
            serde_json::Value::Array(v)
        }
        other => other.clone(),
    }
}

fn load_expected(name: &str, filename: &str) -> serde_json::Value {
    let path = fixture_path(name, filename);
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("[{name}] read {filename}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("[{name}] parse {filename}: {e}"))
}

async fn assert_generate_policies(cfg: GeneratePolicyConfig, name: &str, expected_file: &str) {
    assert!(
        !cfg.extract_sdk_calls_config.source_files.is_empty(),
        "[{name}] fixture needs at least one .py file"
    );

    let result = generate_policies(&cfg)
        .await
        .unwrap_or_else(|e| panic!("[{name}] generate_policies failed: {e}"));

    let actual = normalize(&serde_json::to_value(&result).unwrap());
    let expected = normalize(&load_expected(name, expected_file));

    assert_eq!(
        actual, expected,
        "[{name}] policy output mismatch for {expected_file}"
    );
}

// ===================================================================
// Test: individual policies via --terraform-dir
// ===================================================================

#[rstest]
#[case("basic_multi_resource")]
#[case("variable_resolution")]
#[case("mixed_providers")]
#[case("sub_resource_fallback")]
#[case("mixed_concrete_and_expression")]
#[case("multi_service_real_world")]
#[case("state_precedence")]
#[case("expression_unresolvable")]
#[case("multi_file_resources")]
#[case("multiple_tfvars")]
#[tokio::test]
async fn test_individual_policies(#[case] name: &str) {
    let cfg = GeneratePolicyConfig {
        extract_sdk_calls_config: ExtractSdkCallsConfig {
            source_files: vec![fixture_path(name, "app.py")],
            language: Some("python".to_string()),
            service_hints: None,
        },
        aws_context: aws_context(),
        individual_policies: true,
        minimize_policy_size: false,
        disable_file_system_cache: false,
        explain_filters: None,
        terraform_dir: Some(fixtures_dir().join(name)),
        terraform_files: vec![],
        tfstate_paths: vec![],
        tfvars_files: vec![],
    };
    assert_generate_policies(cfg, name, "expected_policies.json").await;
}

// ===================================================================
// Test: merged policy via --terraform-dir
// ===================================================================

#[rstest]
#[case("basic_multi_resource")]
#[case("variable_resolution")]
#[case("mixed_providers")]
#[case("sub_resource_fallback")]
#[case("mixed_concrete_and_expression")]
#[case("multi_service_real_world")]
#[case("state_precedence")]
#[case("expression_unresolvable")]
#[case("multi_file_resources")]
#[case("multiple_tfvars")]
#[tokio::test]
async fn test_merged_policy(#[case] name: &str) {
    let cfg = GeneratePolicyConfig {
        extract_sdk_calls_config: ExtractSdkCallsConfig {
            source_files: vec![fixture_path(name, "app.py")],
            language: Some("python".to_string()),
            service_hints: None,
        },
        aws_context: aws_context(),
        individual_policies: false,
        minimize_policy_size: false,
        disable_file_system_cache: false,
        explain_filters: None,
        terraform_dir: Some(fixtures_dir().join(name)),
        terraform_files: vec![],
        tfstate_paths: vec![],
        tfvars_files: vec![],
    };
    assert_generate_policies(cfg, name, "expected_merged_policy.json").await;
}

// ===================================================================
// Test: --terraform-file + --tfvars + --tfstate (no directory)
//
// Exercises the code path where all paths are provided explicitly,
// exactly as a CLI user would with individual flags.
// ===================================================================

#[rstest]
// Literal-only: single .tf file
#[case(
    "basic_multi_resource",
    &["app.py"],
    &["main.tf"],
    &[],
    &[]
)]
// Multiple .tf files across the fixture
#[case(
    "multi_file_resources",
    &["app.py"],
    &["storage.tf", "compute.tf"],
    &[],
    &[]
)]
// Sub-resource fallback
#[case(
    "sub_resource_fallback",
    &["app.py"],
    &["main.tf"],
    &[],
    &[]
)]
// Variables resolved via explicit --tfvars
#[case(
    "variable_resolution",
    &["app.py"],
    &["main.tf", "variables.tf"],
    &["terraform.tfvars"],
    &[]
)]
// Multiple --tfvars with precedence chain
#[case(
    "multiple_tfvars",
    &["app.py"],
    &["main.tf", "variables.tf"],
    &["terraform.tfvars", "env.auto.tfvars", "prod.auto.tfvars"],
    &[]
)]
// State file for deployed ARNs
#[case(
    "state_precedence",
    &["app.py"],
    &["main.tf"],
    &[],
    &["terraform.tfstate"]
)]
#[tokio::test]
async fn test_individual_files_mode(
    #[case] name: &str,
    #[case] source_files: &[&str],
    #[case] tf_files: &[&str],
    #[case] tfvars: &[&str],
    #[case] tfstate: &[&str],
) {
    let cfg = GeneratePolicyConfig {
        extract_sdk_calls_config: ExtractSdkCallsConfig {
            source_files: source_files.iter().map(|f| fixture_path(name, f)).collect(),
            language: Some("python".to_string()),
            service_hints: None,
        },
        aws_context: aws_context(),
        individual_policies: true,
        minimize_policy_size: false,
        disable_file_system_cache: false,
        explain_filters: None,
        terraform_dir: None,
        terraform_files: tf_files.iter().map(|f| fixture_path(name, f)).collect(),
        tfstate_paths: tfstate.iter().map(|f| fixture_path(name, f)).collect(),
        tfvars_files: tfvars.iter().map(|f| fixture_path(name, f)).collect(),
    };
    assert_generate_policies(cfg, name, "expected_policies.json").await;
}
