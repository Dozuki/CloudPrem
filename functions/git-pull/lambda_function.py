# Copyright 2017 Amazon Web Services

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import shutil
import stat
import subprocess
from zipfile import ZipFile
from boto3 import client

### If true the function will not include .git folder in the zip
exclude_git = True

### If true the function will delete all files at the end of each invocation, useful if you run into storage space constraints, but will slow down invocations as each invoke will need to checkout the entire repo
cleanup = True

key = 'enc_key'

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.handlers[0].setFormatter(logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s'))
logging.getLogger('boto3').setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.ERROR)

s3 = client('s3')
kms = client('kms')
cp = client('codepipeline')

actionTypeId = {
    'category': 'Source',
    'owner': 'Custom',
    'provider': 'CustomWebhookSourceAction',
    'version': '1'
}


def write_key(filename, contents):
    logger.info('Writing keys to /tmp/...')
    mode = stat.S_IRUSR | stat.S_IWUSR
    umask_original = os.umask(0)

    try:
        handle = os.fdopen(os.open(filename, os.O_WRONLY | os.O_CREAT, mode), 'w')
    finally:
        os.umask(umask_original)

    handle.write(contents + '\n')
    handle.close()


def get_keys(keybucket, update=False):
    if not os.path.isfile('/tmp/id_rsa') or not os.path.isfile('/tmp/id_rsa.pub') or update:
        logger.info('Keys not found on Lambda container, fetching from S3...')
        enckey = s3.get_object(Bucket=keybucket, Key=key)['Body'].read()
        privkey = kms.decrypt(CiphertextBlob=enckey)['Plaintext']
        pubkey = s3.get_object(Bucket=keybucket, Key='pub_key')['Body'].read()

        write_key('/tmp/id_rsa', privkey.decode())
        write_key('/tmp/id_rsa.pub', pubkey.decode())

    # return Keypair('git','/tmp/id_rsa.pub','/tmp/id_rsa','')


def create_repo(repo_path, remote_url, branch):
    if os.path.exists(repo_path):
        logger.info('Cleaning up repo path...')
        shutil.rmtree(repo_path)

    os.environ['GIT_SSH_COMMAND'] = 'ssh -o UserKnownHostsFile=/tmp/known_hosts -i /tmp/id_rsa'

    subprocess.run(f'git clone -b {branch} {remote_url} {repo_path}', shell=True)


def zip_repo(repo_path, repo_name):
    logger.info('Creating zipfile...')
    zf = ZipFile('/tmp/' + repo_name.replace('/', '_') + '.zip', 'w')

    for dirname, subdirs, files in os.walk(repo_path):
        if exclude_git:
            try:
                subdirs.remove('.git')
            except ValueError:
                pass
        zdirname = dirname[len(repo_path) + 1:]
        zf.write(dirname, zdirname)
        for filename in files:
            zf.write(os.path.join(dirname, filename), os.path.join(zdirname, filename))

    zf.close()
    return '/tmp/' + repo_name.replace('/', '_') + '.zip'


def push_s3(filename, repo_name, outputbucket, s3key):
    logger.info('pushing zip to s3://%s/%s' % (outputbucket, s3key))
    data = open(filename, 'rb')
    s3.put_object(Bucket=outputbucket, Body=data, Key=s3key)
    logger.info('Completed S3 upload...')


def pull(job):
    keybucket = os.environ['KEYS_BUCKET']
    outputbucket = job['data']['outputArtifacts'][0]['location']['s3Location']['bucketName']
    outputKey = job['data']['outputArtifacts'][0]['location']['s3Location']['objectKey']

    repo_name = job['data']['pipelineContext']['pipelineName']
    remote_url = job['data']['actionConfiguration']['configuration']['GitUrl']
    branch = job['data']['actionConfiguration']['configuration']['Branch']
    repo_path = '/tmp/%s' % repo_name
    get_keys(keybucket)
    write_key('/tmp/known_hosts',
              'github.com,192.30.252.*,192.30.253.*,192.30.254.*,192.30.255.* ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==')

    logger.info('creating new repo for %s in %s' % (remote_url, repo_path))
    create_repo(repo_path, remote_url, branch)

    zipfile = zip_repo(repo_path, repo_name)
    push_s3(zipfile, repo_name, outputbucket, outputKey)

    revparse_output = subprocess.run('git rev-parse HEAD', capture_output=True, shell=True, cwd=repo_path)
    commit_output = subprocess.run('git show-branch --no-name HEAD', capture_output=True, shell=True, cwd=repo_path)
    created_output = subprocess.run('git --no-pager log -1 --format="%ai"', capture_output=True, shell=True, cwd=repo_path)
    revision = revparse_output.stdout.strip().decode()
    commit_message = commit_output.stdout.strip().decode()
    created = created_output.stdout.strip().decode()

    currentRevision = {
        'revision': revision,
        'changeIdentifier': '???',
        'created': created,
        'revisionSummary': commit_message
    }

    if cleanup:
        logger.info('Cleanup Lambda container...')
        shutil.rmtree(repo_path)
        os.remove(zipfile)
        os.remove('/tmp/id_rsa')
        os.remove('/tmp/id_rsa.pub')

    return currentRevision


def lambda_handler(event, context):
    actionTypeId['version'] = os.environ['CUSTOM_ACTION_VERSION']
    actionTypeId['provider'] = os.environ['CUSTOM_ACTION_PROVIDER']
    print('Polling for jobs!')
    response = cp.poll_for_jobs(actionTypeId=actionTypeId, maxBatchSize=100)
    print('Received {} jobs!'.format(len(response['jobs'])))

    for job in response['jobs']:
        print('Processing job ID {}'.format(job['id']))

        try:
            ack_response = cp.acknowledge_job(jobId=job['id'], nonce=job['nonce'])

            if ack_response['status'] == 'InProgress':
                print('Acknowledged job id {}'.format(job['id']))
                currentRevision = pull(job)
                cp.put_job_success_result(jobId=job['id'], currentRevision=currentRevision)
        except Exception as e:
            cp.put_job_failure_result(jobId=job['id'], failureDetails={'type': 'JobFailed', 'message': str(e)})
            print('Error: ' + str(e))
