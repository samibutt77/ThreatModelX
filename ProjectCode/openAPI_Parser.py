import yaml
import json
from models import SystemModel, Component, DataFlow, DataStore

def parse_openapi(file_path: str) -> SystemModel:
    """
    Parses an OpenAPI (Swagger) file and returns a SystemModel object.
    Extracts:
    - Components: servers or services
    - Data Stores: request/response schemas
    - Data Flows: API calls between services
    """
    system_model = SystemModel()

    # Load YAML or JSON
    with open(file_path, 'r') as f:
        if file_path.endswith(('.yaml', '.yml')):
            spec = yaml.safe_load(f)
        elif file_path.endswith('.json'):
            spec = json.load(f)
        else:
            raise ValueError("Unsupported file type. Use YAML or JSON.")

    # Components: servers or services
    servers = spec.get("servers", [])
    if not servers:
        # If no servers section, create default component
        system_model.add_component(Component(id="APIService", type="api"))
    else:
        for server in servers:
            url = server.get("url", "UnknownServer")
            system_model.add_component(Component(id=url, type="api"))

    # Data Stores: schemas
    components = spec.get("components", {})
    schemas = components.get("schemas", {})
    for schema_name in schemas:
        system_model.add_datastore(DataStore(id=schema_name, type="datastore"))

    # Data Flows: paths -> operations -> request/response
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            operation_id = details.get("operationId", f"{method}_{path}")
            # Assume flow from APIService to Datastore (simplification)
            for response_code, response in details.get("responses", {}).items():
                if "content" in response:
                    for content_type, content_schema in response["content"].items():
                        schema_ref = content_schema.get("schema", {}).get("$ref")
                        if schema_ref:
                            # Extract schema name from $ref: "#/components/schemas/User"
                            schema_name = schema_ref.split("/")[-1]
                            df = DataFlow(source="APIService", target=schema_name)
                            system_model.add_dataflow(df)

    return system_model
