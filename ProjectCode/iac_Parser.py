import yaml
import json
import re
from models import SystemModel, Component, DataFlow, DataStore

def parse_iac(file_path: str) -> SystemModel:
    """
    Parses Terraform (.tf) or CloudFormation (.yaml/.json) files
    and returns a SystemModel object.
    """
    system_model = SystemModel()

    if file_path.endswith(".tf"):
        # Simple Terraform parser (regex-based)
        with open(file_path, 'r') as f:
            content = f.read()

        # Extract resources
        # Example: resource "aws_instance" "web" { ... }
        resource_pattern = re.compile(r'resource\s+"(\w+)"\s+"(\w+)"')
        matches = resource_pattern.findall(content)
        for r_type, r_name in matches:
            comp = Component(id=r_name, type=r_type)
            system_model.add_component(comp)

        # Extract potential data stores (e.g., aws_s3_bucket, aws_db_instance)
        datastore_types = ["aws_s3_bucket", "aws_db_instance", "aws_dynamodb_table"]
        for r_type, r_name in matches:
            if r_type in datastore_types:
                ds = DataStore(id=r_name, type=r_type)
                system_model.add_datastore(ds)

        # Naive flow: all components -> all datastores
        for c in system_model.components:
            for d in system_model.datastores:
                df = DataFlow(source=c.id, target=d.id)
                system_model.add_dataflow(df)

    elif file_path.endswith((".yaml", ".yml", ".json")):
        # CloudFormation parser
        with open(file_path, 'r') as f:
            if file_path.endswith((".yaml", ".yml")):
                template = yaml.safe_load(f)
            else:
                template = json.load(f)

        resources = template.get("Resources", {})
        for r_name, r_def in resources.items():
            r_type = r_def.get("Type", "Unknown")
            comp = Component(id=r_name, type=r_type)
            system_model.add_component(comp)

            # Identify data stores
            datastore_types = [
                "AWS::S3::Bucket",
                "AWS::RDS::DBInstance",
                "AWS::DynamoDB::Table"
            ]
            if r_type in datastore_types:
                ds = DataStore(id=r_name, type=r_type)
                system_model.add_datastore(ds)

        # Naive flow: all components -> all datastores
        for c in system_model.components:
            for d in system_model.datastores:
                df = DataFlow(source=c.id, target=d.id)
                system_model.add_dataflow(df)

    else:
        raise ValueError("Unsupported file type. Use .tf, .yaml, .yml, or .json.")

    return system_model
