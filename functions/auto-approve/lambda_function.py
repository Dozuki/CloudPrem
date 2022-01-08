import json
import boto3

print('Loading function')
cp = boto3.client('codepipeline')


def lambda_handler(event, context):
    # print("Received event: " + json.dumps(event, indent=2))
    message = json.loads(event['Records'][0]['Sns']['Message'])
    approval = message['approval']
    pipeline_name = approval['pipelineName']
    stage_name = approval['stageName']
    action_name = approval['actionName']
    token = approval['token']
    plan = approval['customData']
    if plan == 'No Changes':
        print('Auto Approving null plan')
        response = cp.put_approval_result(
            pipelineName=pipeline_name,
            stageName=stage_name,
            actionName=action_name,
            result={
                'summary': 'Auto Approving due to 0 planned changes.',
                'status': 'Approved'
            },
            token=token
        )
        result = "Approved at: " + response['approvedAt'].strftime("%H:%M:%S")
    else:
        result = 'Plan has changes, not autoapproving'
    print(result)
