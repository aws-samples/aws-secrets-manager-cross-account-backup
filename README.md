## AWS Secrets Manager Cross Account Backup

As a disaster recovery solution, having regular backups of AWS Secrets Manager secrets in a separate, hardened AWS account will allow the recovery of secrets should the original secrets be lost through accidental deletion.  This pattern will automate this process by hooking into AWS Secrets Manager secret creation and modification API calls and triggering an AWS Lambda function in the backup account to access the relevant source account and retrieve the secret value along with its metadata.

## Usage

1. Clone the repository and upload the files found in the `scripts/` and `templates/` directory to an S3 bucket.  Ensure that this bucket has a policy that allows read access for the AWS accounts you identify as the source of the AWS Secrets Manager secrets along with the AWS account identified as the backup for those secrets.

2. Once the files have been uploaded to an S3 bucket, launch the CloudFormation template `secrets_manager_backup.baseline.template.yml` in the administrator account.  You may use a local copy of the template or reference the same template previously uploaded to an S3 bucket.

3. After launching the baseline template, locate the `Secrets Manager Backup` product now available via Service Catalog.  Providing the relevant AWS account IDs and other parameters, launch the product.

4. Once the AWS Service Catalog product has completed launching, access an AWS account identified as a backup source and modify/create an AWS Secrets Manager secret.  Once done, access the AWS account identified as the backup account and ensure that the modified/created secret exists with the name format "\<ACCOUNT>/\<REGION>/\<SOURCE NAME>".

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

