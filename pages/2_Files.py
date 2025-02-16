import streamlit as st
import os
import boto3
from dotenv import load_dotenv
from botocore.exceptions import ClientError
import io
import json
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
from demo_tools.retries import wait

# Load environment variables
load_dotenv()

ROLE_POLICY_NAME = "agent_permissions"

# Configure page
st.set_page_config(
    page_title="Files - HR Assistant",
    page_icon="📁",
    layout="wide"
)

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

BUCKET_NAME = os.getenv('BUCKET_NAME', 'chat-ai')  # Get from env or use default
PROJECT_NAME = os.getenv('PROJECT_NAME', 'hr-assistant')  # Get from env or use default
BUCKET_NAME = f'{BUCKET_NAME}-{PROJECT_NAME}'

def list_s3_files():
    """List all files in the S3 bucket"""
    try:
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME)
        files = []
        if 'Contents' in response:
            files = [obj['Key'] for obj in response['Contents']]
        return files
    except ClientError as e:
        st.error(f"Error listing files: {str(e)}")
        return []

def upload_to_s3(file_obj, filename):
    """Upload a file to S3"""
    try:
        s3_client.upload_fileobj(file_obj, BUCKET_NAME, filename)
        return True
    except ClientError as e:
        st.error(f"Error uploading file: {str(e)}")
        return False

def delete_from_s3_and_opensearch(filename):
    """Delete a file from S3 and remove its entries from OpenSearch"""
    try:
        # Delete from S3
        s3_client.delete_object(Bucket=BUCKET_NAME, Key=filename)
        
        # Delete from OpenSearch
        opensearch_client = get_opensearch_client()
        index_name = f"docs-{PROJECT_NAME}"
        
        # Delete all chunks associated with this file
        query = {
            "query": {
                "match": {
                    "filename.keyword": filename
                }
            }
        }
        
        try:
            opensearch_client.delete_by_query(
                index=index_name,
                body=query
            )
        except Exception as e:
            st.warning(f"Note: Could not delete from knowledge base: {str(e)}")
        
        return True
    except ClientError as e:
        st.error(f"Error deleting file: {str(e)}")
        return False

def read_file_from_s3(filename):
    """Read a file's content from S3"""
    try:
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=filename)
        return response['Body'].read().decode('utf-8')
    except ClientError as e:
        st.error(f"Error reading file: {str(e)}")
        return None

def ensure_bucket_exists():
    """Check if bucket exists and create it if it doesn't"""
    try:
        s3_client.head_bucket(Bucket=BUCKET_NAME)
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == '404' or error_code == '403':
            try:
                # For regions other than us-east-1, we need to specify LocationConstraint
                region = os.getenv('AWS_DEFAULT_REGION')
                if region == 'us-east-1':
                    s3_client.create_bucket(Bucket=BUCKET_NAME)
                else:
                    s3_client.create_bucket(
                        Bucket=BUCKET_NAME,
                        CreateBucketConfiguration={'LocationConstraint': region}
                    )
                st.success(f"Created new S3 bucket: {BUCKET_NAME}")
                return True
            except ClientError as create_error:
                st.error(f"Error creating bucket: {str(create_error)}")
                return False
        else:
            st.error(f"Error checking bucket: {str(e)}")
            return False
    return True

# Ensure bucket exists before proceeding
if not ensure_bucket_exists():
    st.error("Unable to initialize storage. Please check your AWS credentials and permissions.")
    st.stop()

# Initialize session state for uploaded files if not exists
if "uploaded_files" not in st.session_state:
    st.session_state.uploaded_files = []

# Initialize OpenSearch client
def get_opensearch_client():
    """Get OpenSearch client for serverless"""
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        os.getenv('AWS_DEFAULT_REGION'),
        'aoss',  # Service name for OpenSearch Serverless
        session_token=credentials.token
    )
    
    opensearch_client = OpenSearch(
        hosts=[{'host': os.getenv('OPENSEARCH_ENDPOINT'), 'port': 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )
    return opensearch_client

def manage_opensearch_collection():
    """Create or recreate OpenSearch Serverless collection"""
    try:
        # Initialize OpenSearch Serverless client
        opensearch_client = boto3.client('opensearchserverless')
        collection_name = f"docs-{PROJECT_NAME}"
        
        # Check and delete existing collection
        try:
            st.info(f"Checking for existing collection: {collection_name}")
            collections = opensearch_client.list_collections()
            for collection in collections.get('collectionSummaries', []):
                if collection['name'] == collection_name:
                    st.warning(f"Deleting existing collection: {collection_name}")
                    opensearch_client.delete_collection(
                        Id=collection_name
                    )
                    # Wait for collection to be deleted
                    waiter = opensearch_client.get_waiter('collection_deleted')
                    with st.spinner("Waiting for collection deletion..."):
                        waiter.wait(Id=collection_name)
                    st.success("Previous collection deleted")
                    break
        except Exception as e:
            st.info(f"No existing collection found or error checking: {str(e)}")

        # Create security policy
        policy_name = f"policy-{collection_name}"
        policy_document = {
            "Rules": [
                {
                    "ResourceType": "collection",
                    "Resource": [
                        f"collection/{collection_name}"
                    ],
                    "Permission": [
                        "aoss:*"
                    ]
                },
                {
                    "ResourceType": "index",
                    "Resource": [
                        f"index/{collection_name}/*"
                    ],
                    "Permission": [
                        "aoss:*"
                    ]
                }
            ],
            "Principal": [
                f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:root"
            ]
        }

        # Create or update security policy
        try:
            opensearch_client.create_security_policy(
                name=policy_name,
                policy=json.dumps(policy_document),
                type='encryption'
            )
        except opensearch_client.exceptions.ConflictException:
            opensearch_client.update_security_policy(
                name=policy_name,
                policy=json.dumps(policy_document),
                type='encryption'
            )

        # Create access policy
        network_policy_name = f"network-{collection_name}"
        network_policy = {
            "Rules": [
                {
                    "ResourceType": "collection",
                    "Resource": [
                        f"collection/{collection_name}"
                    ],
                    "Permission": [
                        "aoss:*"
                    ]
                }
            ],
            "Principal": [
                f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:root"
            ]
        }

        # Create or update network policy
        try:
            opensearch_client.create_security_policy(
                name=network_policy_name,
                policy=json.dumps(network_policy),
                type='network'
            )
        except opensearch_client.exceptions.ConflictException:
            opensearch_client.update_security_policy(
                name=network_policy_name,
                policy=json.dumps(network_policy),
                type='network'
            )

        # Create new collection
        st.info("Creating new OpenSearch Serverless collection...")
        response = opensearch_client.create_collection(
            name=collection_name,
            type='VECTORSEARCH',
            description=f'Vector search collection for {PROJECT_NAME}',
        )
        
        # Wait for collection to be created
        waiter = opensearch_client.get_waiter('collection_active')
        with st.spinner("Waiting for collection to be available..."):
            waiter.wait(Id=collection_name)
        
        # Get collection endpoint
        collection_info = opensearch_client.list_collections(
            collectionFilters={
                'name': collection_name
            }
        )
        endpoint = collection_info['collectionSummaries'][0]['collectionEndpoint']
        
        st.success(f"New OpenSearch Serverless collection created successfully!")
        return endpoint
        
    except Exception as e:
        st.error(f"Error managing OpenSearch collection: {str(e)}")
        return None

def process_and_embed_files():
    """Process all files in S3 bucket and create embeddings"""
    try:
        # First recreate the OpenSearch collection
        st.info("Setting up OpenSearch Serverless collection...")
        endpoint = manage_opensearch_collection()
        if not endpoint:
            st.error("Failed to set up OpenSearch collection")
            return
            
        # Update the OPENSEARCH_ENDPOINT in environment
        os.environ['OPENSEARCH_ENDPOINT'] = endpoint
        
        # Get list of files
        files = list_s3_files()
        if not files:
            st.warning("No files found in the bucket to process")
            return
        
        # Initialize Bedrock client
        bedrock = boto3.client(
            service_name='bedrock-runtime',
            region_name=os.getenv('AWS_DEFAULT_REGION')
        )
        
        opensearch_client = get_opensearch_client()
        index_name = f"docs-{PROJECT_NAME}"
        
        # Delete existing index if it exists
        if opensearch_client.indices.exists(index_name):
            st.info(f"Deleting existing index: {index_name}")
            opensearch_client.indices.delete(index=index_name)
            st.success("Previous knowledge base deleted")
        
        # Create new index
        st.info("Creating new knowledge base...")
        index_body = {
            'settings': {
                'index': {
                    'knn': True,
                }
            },
            'mappings': {
                'properties': {
                    'content_vector': {
                        'type': 'knn_vector',
                        'dimension': 1536  # Dimension for Titan embedding
                    },
                    'content': {'type': 'text'},
                    'filename': {'type': 'keyword'},
                    'chunk_id': {'type': 'keyword'}
                }
            }
        }
        opensearch_client.indices.create(index_name, body=index_body)
        st.success("New knowledge base created")
        
        # Process files
        progress_bar = st.progress(0)
        status_text = st.empty()
        total_chunks = 0
        processed_chunks = 0
        
        # First pass: count total chunks
        for filename in files:
            content = read_file_from_s3(filename)
            if content:
                chunks = [content[i:i+1000] for i in range(0, len(content), 1000)]
                total_chunks += len(chunks)
        
        # Second pass: process and embed
        for filename in files:
            status_text.text(f"Processing {filename}...")
            
            content = read_file_from_s3(filename)
            if not content:
                continue
            
            chunks = [content[i:i+1000] for i in range(0, len(content), 1000)]
            
            for chunk_id, chunk in enumerate(chunks):
                try:
                    # Get embeddings using Bedrock
                    response = bedrock.invoke_model(
                        modelId="amazon.titan-embed-text-v1",
                        body=json.dumps({
                            "inputText": chunk
                        })
                    )
                    embedding = json.loads(response['body'].read())['embedding']
                    
                    # Index in OpenSearch
                    doc = {
                        'content_vector': embedding,
                        'content': chunk,
                        'filename': filename,
                        'chunk_id': f"{filename}-{chunk_id}"
                    }
                    opensearch_client.index(
                        index=index_name,
                        body=doc,
                        id=f"{filename}-{chunk_id}"
                    )
                    
                    processed_chunks += 1
                    progress_bar.progress(processed_chunks / total_chunks)
                    status_text.text(f"Processing {filename} - Chunk {chunk_id + 1}/{len(chunks)}")
                    
                except Exception as e:
                    st.error(f"Error processing chunk {chunk_id} of {filename}: {str(e)}")
                    continue
        
        status_text.text("All files processed successfully!")
        st.success(f"Documents have been embedded and indexed in OpenSearch. Total chunks processed: {processed_chunks}")
        
    except Exception as e:
        st.error(f"Error processing files: {str(e)}")

def create_agent():
    """Create a new Bedrock agent"""
    try:
        # Initialize Bedrock agent client
        bedrock_agent = boto3.client('bedrock-agent')
        agent_name = f"agent-{PROJECT_NAME}"
        
        # Check and delete existing agent
        try:
            st.info(f"Checking for existing agent: {agent_name}")
            existing_agents = bedrock_agent.list_agents()
            for agent in existing_agents.get('agentSummaries', []):
                if agent['agentName'] == agent_name:
                    st.warning(f"Deleting existing agent: {agent_name}")
                    bedrock_agent.delete_agent(
                        agentId=agent['agentId']
                    )
                    # Wait for agent to be deleted
                    waiter = bedrock_agent.get_waiter('agent_deleted')
                    with st.spinner("Waiting for agent deletion..."):
                        waiter.wait(agentId=agent['agentId'])
                    st.success("Previous agent deleted")
                    break
        except Exception as e:
            st.info(f"No existing agent found or error checking: {str(e)}")

        # Create knowledge base if it doesn't exist
        kb_name = f"kb-{PROJECT_NAME}"
        try:
            knowledge_base = bedrock_agent.create_knowledge_base(
                name=kb_name,
                description=f"Knowledge base for {PROJECT_NAME}",
                roleArn=f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:role/service-role/AmazonBedrockExecutionRoleForAgent",
                knowledgeBaseConfiguration={
                    'type': 'VECTOR',
                    'vectorKnowledgeBaseConfiguration': {
                        'embeddingModelArn': 'arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v1'
                    }
                }
            )
            st.success("Created knowledge base")
        except bedrock_agent.exceptions.ConflictException:
            st.info("Knowledge base already exists")
            knowledge_bases = bedrock_agent.list_knowledge_bases()
            knowledge_base = next(kb for kb in knowledge_bases['knowledgeBaseSummaries'] 
                                if kb['name'] == kb_name)

        # Create new agent
        st.info("Creating new Bedrock agent...")
        agent = bedrock_agent.create_agent(
            agentName=agent_name,
            description=f"Agent for {PROJECT_NAME}",
            instruction="You are an HR assistant. Use the knowledge base to answer questions about HR policies and procedures.",
            foundationModel="anthropic.claude-3-5-haiku-20241022-v1:0",
            roleArn=f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:role/service-role/AmazonBedrockExecutionRoleForAgent",
            idleSessionTTLInSeconds=1800,  # 30 minutes
            knowledgeBases=[{
                'knowledgeBaseId': knowledge_base['knowledgeBaseId']
            }],
            storageConfiguration= {
                'type': 'S3',  # Using S3 storage for vector data
                's3Config': {
                    'bucket': 'chat-ai-hr-assistant',  # Replace with your S3 bucket
                    'prefix': '',  # Prefix for storing the data
                }
            },
        )
        
        # Wait for agent to be created
        waiter = bedrock_agent.get_waiter('agent_available')
        with st.spinner("Waiting for agent to be available..."):
            waiter.wait(agentId=agent['agentId'])
        
        # Create agent alias
        alias = bedrock_agent.create_agent_alias(
            agentId=agent['agentId'],
            agentAliasName='LATEST',
            description='Latest version of the agent'
        )
        
        st.success(f"New Bedrock agent created successfully! Agent ID: {agent['agentId']}")
        return agent['agentId']
        
    except Exception as e:
        st.error(f"Error creating Bedrock agent: {str(e)}")
        return None

def create_bedrock_instance():
    try:
        # Define the parameters for the Bedrock instance
        bedrock_agent = boto3.client('bedrock', region_name=os.getenv('AWS_DEFAULT_REGION'))  # Change region as needed
        response = bedrock_agent.create_instance(
            name='hr-assistant',  # Name of the Bedrock instance
            description='Knowledge base with vector search',
            storageConfiguration= {
                'type': 'S3',  # Using S3 storage for vector data
                's3Config': {
                    'bucket': 'chat-ai-hr-assistant',  # Replace with your S3 bucket
                    'prefix': '',  # Prefix for storing the data
                }
            },
            knowledgeBaseConfiguration={
                'vectorSearch': True,  # Enabling vector search on the knowledge base
                'vectorIndex': {
                    'type': 'FAISS',  # Example of vector index, FAISS is commonly used
                    'dimension': 1536  # Adjust based on your vector size
                }
            }
        )

        print("Bedrock instance created successfully:")
        print(response)
    
    except Exception as e:
        print(f"Error creating Bedrock instance: {e}")

def create_bedrock_agent(agent_name, description, storage_configuration, knowledge_base_configuration, region_name):
    client = boto3.client('bedrock-agent', region_name=region_name)
    try:
        response = client.create_agent(
            agentName=agent_name,
            description=description,
            storageConfiguration=storage_configuration,
            knowledgeBaseConfiguration=knowledge_base_configuration
        )
        return response
    except Exception as e:
        print(f"Error creating Bedrock agent: {e}")
        raise

def prepare_agent(agent_id):
    bedrock_agent_client = boto3.client('bedrock-agent', region_name=os.getenv('AWS_DEFAULT_REGION'))
    try:
        prepared_agent_details = bedrock_agent_client.prepare_agent(agentId=agent_id)
        wait_for_agent_status(agent_id, "PREPARED")
    except ClientError as e:
        print(f"Couldn't prepare agent. {e}")
        raise
    else:
        return prepared_agent_details

def wait_for_agent_status(agent_id, status, wait_time=5):
    print("Waiting for the " + agent_id + " to be " + status + "...")
    bedrock_agent_client = boto3.client('bedrock-agent', region_name=os.getenv('AWS_DEFAULT_REGION'))
    agentId, agentName, agentStatus = get_agent_status(agent_id)
    
    print("Waiting for the " + agentName + " to be " + status + "...")

    while agentStatus != status:
        print("Waiting for the " + agent_id + " to be " + status + "...")
        agentId, agentName, agentStatus = get_agent_status(agent_id)
        print("Agent ID: " + agentId)
        print("Agent Name: " + agentName)
        print("Agent Status: " + agentStatus)
        wait(wait_time)

    print("Agent " + agentName + " is now in " + status + " status")
    print("-------------------------------- DONE WAITING...")

def get_agent_status(agent_id):
    bedrock_agent_client = boto3.client('bedrock-agent', region_name=os.getenv('AWS_DEFAULT_REGION'))
    try:
        agent = bedrock_agent_client.get_agent(agentId=agent_id)
        agentName = agent["agent"]["agentName"]
        agentId = agent["agent"]["agentId"]
        agentStatus = agent["agent"]["agentStatus"]
        return agentId, agentName, agentStatus
    except ClientError as e:
        print(f"Error getting agent status: {e}")
        return agent_id, "", "DELETED"

def create_agent_alias(name, agent_id):
    bedrock_agent_client = boto3.client('bedrock-agent', region_name=os.getenv('AWS_DEFAULT_REGION'))

    try:
        response = bedrock_agent_client.create_agent_alias(
            agentAliasName=name, 
            agentId=agent_id
        )
        agent_alias = response["agentAlias"]
        agentStatus = "PREPARED"

        wait_for_agent_status(agent_id, agentStatus)

    except ClientError as e:
        raise
    else:
        return agent_alias

def create_agent_now(name, foundation_model_id, instruction, agent_role): 
    print("STARTING TO CREATE THE AGENT...")
    bedrock_agent_client = boto3.client('bedrock-agent', region_name=os.getenv('AWS_DEFAULT_REGION'))

    # Check if the agent already exists
    print("Checking if the agent already exists..." + str(bedrock_agent_client.list_agents()))
    print("--------------------------------")
    existing_agents = bedrock_agent_client.list_agents()["agentSummaries"]
    print("--------------------------------")
    print("Existing agents: " + str(existing_agents))
    print("--------------------------------")

    for agent in existing_agents:
        if agent["agentName"] == name:
            agentId = agent["agentId"]
            print(f"Agent {name} already exists. Deleting the existing agent...")
            bedrock_agent_client.delete_agent(agentId=agentId)
            agentStatus = "DELETED"
            print("Waiting for the agent to be deleted...")
            wait_for_agent_status(agentId, agentStatus)  # Wait for the agent to be deleted
            print("Agent deleted successfully.")
            break

    print("Creating the agent...")

    instruction = """
        You are a friendly chat bot. You have access to a function called that returns
        information about the current date and time. When responding with date or time,
        please make sure to add the timezone UTC.
        """
    agent = bedrock_agent_client.create_agent(
        agentName=name,
        foundationModel=foundation_model_id,
        instruction=instruction,
        agentResourceRoleArn=agent_role.arn,
    )
    print("--------------------------------")
    print("Agent created successfully: " + str(agent))
    print("--------------------------------")
    agentId = agent['agent']['agentId']
    print(f"Extracted agentId: {agentId}")
    agentStatus = "NOT_PREPARED"
    wait_for_agent_status(agentId, agentStatus)

    return agent

def create_agent_alias(name, agent_id):
    print("STARTING TO CREATE AN AGENT ALIAS...")
    client = boto3.client('bedrock-agent', region_name=os.getenv('AWS_DEFAULT_REGION'))
    try:
        print("Creating an agent alias...")
        response = client.create_agent_alias(
            agentAliasName=name, 
            agentId=agent_id
        )
        agent_alias = response["agentAlias"]
        print("Agent alias created successfully: " + str(agent_alias))
    except ClientError as e:
        print(f"Couldn't create agent alias. {e}")
        raise
    else:
        print("Agent alias created successfully: " + str(agent_alias))
        return agent_alias

@staticmethod
def _create_deployment_package(function_name):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zipped:
        zipped.write(
            "./scenario_resources/lambda_function.py", f"{function_name}.py"
        )
    buffer.seek(0)
    return buffer.read()

def create_lambda_function(postfix, function_name, lambda_client):
        print("Creating the Lambda function...")

        function_name = f"AmazonBedrockExampleFunction_{postfix}"

        lambda_role = create_lambda_role(postfix)

        try:
            deployment_package = create_deployment_package(function_name)

            lambda_function = lambda_client.create_function(
                FunctionName=function_name,
                Description="Lambda function for Amazon Bedrock example",
                Runtime="python3.11",
                Role=lambda_role.arn,
                Handler=f"{function_name}.lambda_handler",
                Code={"ZipFile": deployment_package},
                Publish=True,
            )

            waiter = lambda_client.get_waiter("function_active_v2")
            waiter.wait(FunctionName=function_name)

        except ClientError as e:
            print(f"Couldn't create Lambda function {function_name}. Here's why: {e}")
            raise

        return lambda_function

def create_lambda_role(self):
    print("Creating an execution role for the Lambda function...")

    role_name = f"AmazonBedrockExecutionRoleForLambda_{self.postfix}"

    try:
        role = self.iam_resource.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )
        role.attach_policy(
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
        print(f"Created role {role_name}")
    except ClientError as e:
        print(f"Couldn't create role {role_name}. Here's why: {e}")
        raise

    print("Waiting for the execution role to be fully propagated...")
    wait(10)

    return role

def allow_agent_to_invoke_function(self):
    policy = self.iam_resource.RolePolicy(
        self.agent_role.role_name, ROLE_POLICY_NAME
    )
    doc = policy.policy_document
    doc["Statement"].append(
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": self.lambda_function["FunctionArn"],
        }
    )
    self.agent_role.Policy(ROLE_POLICY_NAME).put(PolicyDocument=json.dumps(doc))

def let_function_accept_invocations_from_agent(self):
    try:
        self.lambda_client.add_permission(
            FunctionName=self.lambda_function["FunctionName"],
            SourceArn=self.agent["agentArn"],
            StatementId="BedrockAccess",
            Action="lambda:InvokeFunction",
            Principal="bedrock.amazonaws.com",
        )
    except ClientError as e:
        print(f"Couldn't grant Bedrock permission to invoke the Lambda function. Here's why: {e}")
        raise

def create_agent_role(postfix, foundation_model_id, region):
        print("Creating an execution role for the agent...")
        role_name = f"AmazonBedrockExecutionRoleForAgents_{postfix}"
        iam_resource = boto3.resource("iam")  # Ensure iam_resource is defined

        # Check if the role exists and delete it if it does
        try:
            existing_role = iam_resource.Role(role_name)
            existing_role.load()  # Load the role to check if it exists
            print(f"Deleting existing role: {role_name}...")
            existing_role.Policy(ROLE_POLICY_NAME).delete()  # Delete the policy
            existing_role.delete()  # Delete the role
            print(f"Role {role_name} deleted successfully.")
        except ClientError as e:
            print(f"Error deleting role: {e}")
            if e.response['Error']['Code'] != 'NoSuchEntity':
                raise  # Raise if the error is not about the role not existing
            print(f"Role {role_name} does not exist, proceeding to create a new one.")

        model_arn = f"arn:aws:bedrock:{region}::foundation-model/{foundation_model_id}*"

        print("Creating an execution role for the agent...")

        try:
            print("Creating a new role...")
            role = iam_resource.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "bedrock.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                ),
            )
            print("Role created successfully: " + str(role))


            role.Policy(ROLE_POLICY_NAME).put(
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "bedrock:InvokeModel",
                                "Resource": model_arn,
                            }
                        ],
                    }
                )
            )
            print("Policy created successfully: " + str(role.Policy(ROLE_POLICY_NAME)))
        except ClientError as e:
            print(f"Error creating role: {e}")
            raise

        print("Role created successfully: " + str(role))
        return role
# Add button to sidebar
with st.sidebar:
    st.markdown("---")
    if st.button("🔄 Recreate Agent", help="Delete and recreate bedrock client"):
        with st.spinner("Initializing agent..."):

            my_model_id = 'anthropic.claude-3-5-haiku-20241022-v1:0'
            my_agent_name = 'hr-assistant'
            iam_resource=boto3.resource("iam")
            region=os.getenv('AWS_DEFAULT_REGION')
            lambda_client=boto3.client(service_name="lambda", region_name=region)
            instruction = """
                You are a friendly chat bot. You have access to a function called that returns
                information about the current date and time. When responding with date or time,
                please make sure to add the timezone UTC.
                """

            agent_role = create_agent_role(
                postfix=my_agent_name, 
                foundation_model_id=my_model_id,
                region=region
            )

            agent = create_agent_now(
                name=my_agent_name, 
                foundation_model_id=my_model_id,
                instruction=instruction,
                agent_role=agent_role
            )

            prepare_agent(agent['agent']['agentId'])

            create_agent_alias(my_agent_name, agent['agent']['agentId'])

            create_lambda_function(self)

            allow_agent_to_invoke_function(self)

            let_function_accept_invocations_from_agent(self)



# Add button to sidebar
with st.sidebar:
    st.markdown("---")
    if st.button("🔄 Recreate Knowledge Base", help="Delete and recreate OpenSearch collection, then process all files"):
        with st.spinner("Initializing knowledge base..."):
            process_and_embed_files()

st.title("📁 Knowledge Base File Management")

# File upload section
st.header("Upload Files")
uploaded_file = st.file_uploader(
    "Choose a file to upload",
    type=["txt", "pdf", "doc", "docx"],
    help="Supported formats: TXT, PDF, DOC, DOCX"
)

if uploaded_file is not None:
    # Upload to S3
    if upload_to_s3(uploaded_file, uploaded_file.name):
        st.success(f"File uploaded successfully: {uploaded_file.name}")
        # Refresh the file list
        st.session_state.uploaded_files = list_s3_files()
    else:
        st.error("Failed to upload file")

# Display uploaded files
st.header("Uploaded Files")
# Refresh file list from S3
files = list_s3_files()
if not files:
    st.info("No files uploaded yet.")
else:
    for filename in files:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.write(filename)
        with col2:
            if st.button("View", key=f"view_{filename}"):
                content = read_file_from_s3(filename)
                if content:
                    st.text_area("File Content", content, height=200)
        with col3:
            if st.button("Delete", key=f"delete_{filename}"):
                if delete_from_s3_and_opensearch(filename):
                    st.success(f"Deleted {filename} from storage and knowledge base")
                    # Refresh the file list
                    st.rerun() 