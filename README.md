# CloudPrem Distribution Pipelines

This repository contains the CloudFormation templates for the CloudPrem distribution pipelines. The pipelines use CodeBuild and CodePipeline to automate the deployment of the CloudPrem Terraform infrastructure.

The pipelines infrastructure is defined across two CloudFormation templates:
1. Cloudprem CodePipeline: Contains shared resources and configurations for CodePipeline
2. Cloudprem Pipeline: Contains the resources for a deployment pipeline for a specific environment

### Cloudprem Codepipeline 

|||
|-|-|
| AWS | [![launch_stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home#/stacks/new?stackName=cloudprem-codepipeline&templateURL=https://s3.us-west-2.amazonaws.com/nclouds-cloudprem-assets/codepipeline_app.yml) |
| GovCloud | [![launch_stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.amazonaws-us-gov.com/cloudformation/home#/stacks/new?stackName=cloudprem-codepipeline&templateURL=https://s3.us-west-2.amazonaws.com/nclouds-cloudprem-assets/codepipeline_app.yml) |

The Cloudprem CodePipeline stack should be deployed once in every region you intend to deploy the CloudPrem infrastructure. This stack will create a Serverless Application which in turn creates an S3 artifacts bucket for CodePipeline as well as a custom source action to pull the source code from any git repository. The stack creates some stack exports that will be used by the Cloudprem pipelines.

| Parameter            | Description                                                                          | Default | Required |
|----------------------|--------------------------------------------------------------------------------------|---------|----------|
| SourceActionVersion  | Version of the custom source action for CodePipeline. Update the version if required | 1       | no       |
| SourceActionProvider | Provider name of the custom source action for CodePipeline                           | Git     | no       |
| OwnerName            | An arbitrary tag name for the owner of the Stack                                     |         | yes      |


### Cloudprem Pipeline 

|||
|-|-|
| AWS | [![launch_stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home#/stacks/new?stackName=cloudprem-pipeline-dev&templateURL=https://s3.us-west-2.amazonaws.com/nclouds-cloudprem-assets/git_pipeline.yml) |
| GovCloud | [![launch_stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.amazonaws-us-gov.com/cloudformation/home#/stacks/new?stackName=cloudprem-pipeline-dev&templateURL=https://s3.us-west-2.amazonaws.com/nclouds-cloudprem-assets/git_pipeline.yml) |

The Cloudprem Pipeline stack should be deployed once per environment. It deploys the actual pipeline as well as the CodeBuild projects for the pipeline execution.

![distribution-pipeline-git](https://app.lucidchart.com/publicSegments/view/d764e658-a737-4656-bd90-a6a2ea69f891/image.png)

| Parameter        | Description                                                                                                                                | Default                                                | Required |
|------------------|--------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|----------|
| DozukiLicense    | The contents of the .rli license file provided by Dozuki                                                                                   |                                                        | yes      |
| RepositoryUrl    | SSH/HTTP URL of the git repository containing the Cloudprem parameters                                                                     | https://github.com/nclouds/doz-infrastructure-live.git | no       |
| RepositoryBranch | Branch that contains the Cloudprem parameters                                                                                              | main                                                   | no       |
| RepositoryPath   | Path inside the git repository that contains the Cloudprem parameters for this environment. Don't use the same path for multiple pipelines | development                                            | no       |
| OverrideRepositoryParameters | Override 'Region' and 'Environment' parameters from the repository with the current template parameters                                    | true                                                   | no       |
| PipelineAction   | Action that the pipeline will execute. Apply will create or update the resources and destroy will delete the Terraform stack               | Apply                                                  | no       |                                                       |          |
| Identifier       | A name identifier to add as prefix to resources names                                                                                    |  "" | no
| OwnerName        | An arbitrary tag name for the owner of the environment pipeline                                                                            |                                                        | yes      |
| Environment      | Environment name to append to resources names and tags                                                                                     | dev                                                    | no       |

The pipeline supports two types of repositories, public and private:

#### Public

For public repositories you should use the **https** URL of the git repository. Then no further action is needed. The default repository is the Dozuki repository which contains the recommended parameters by Dozuki. If you want to customize the parameters used for your stack copy the repository and update the input values for each environment.

#### Private

For private repositories you must use the **ssh** URL of the git repository. The Stack will create a pair of SSH keys to authenticate, you must add the public key to your user authorized keys:

1. Go to the *Cloudprem CodePipeline* Stack that you previously deployed and in the outputs tab, copy the public ssh key.
2. Go to your user settings and choose SSH and GPG Keys. Add a new SSH key with the PublicSSHKey value from AWS CloudFormation.

*(Notes: If you are not using the 'OverrideRepositoryParameters' setting Make sure to use the same environment name on the CloudFormation template and the Terraform parameters. The cloudformation template creates an SSM parameter with a specific name that must be used by Terraform so make sure you set the value correctly)*