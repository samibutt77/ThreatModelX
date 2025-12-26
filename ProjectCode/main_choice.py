from UMLParser import parse_uml
from openAPI_Parser import parse_openapi
from iac_Parser import parse_iac
from source_code_Parser import parse_source_code
from models import SystemModel
from threatEngine import ThreatEngine

def get_file_path(parser_name):
    path = input(f"Enter the file path for {parser_name} (or leave blank to skip): ").strip()
    # Remove surrounding quotes if user accidentally added them
    if path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    return path if path else None

def parse_and_add(parser_name, parse_func, file_path, system_model):
    model = parse_func(file_path)
    print(f"\n=== {parser_name} Parser Output ===")
    if hasattr(model, 'components') and model.components:
        print("Components:")
        for c in model.components:
            boundary = getattr(c, "boundary", None)
            print(f"- {c.id} (Boundary: {boundary})" if boundary else f"- {c.id} ({c.type})")
    if hasattr(model, 'datastores') and model.datastores:
        print("Data Stores:")
        for d in model.datastores:
            boundary = getattr(d, "boundary", None)
            print(f"- {d.id} (Boundary: {boundary})" if boundary else f"- {d.id} ({d.type})")
    if hasattr(model, 'dataflows') and model.dataflows:
        print("Data Flows:")
        for f in model.dataflows:
            print(f"- {f.source} -> {f.target}")

    # Merge into system model
    if hasattr(model, 'components'):
        for c in model.components:
            system_model.add_component(c)
    if hasattr(model, 'datastores'):
        for d in model.datastores:
            system_model.add_datastore(d)
    if hasattr(model, 'dataflows'):
        for f in model.dataflows:
            system_model.add_dataflow(f)

def main():
    system_model = SystemModel()

    print("=== Automated Threat Modeling Toolkit ===")
    print("Select which parsers you want to run (enter numbers separated by comma):")
    print("1. UML/PlantUML")
    print("2. OpenAPI/Swagger")
    print("3. IaC (Terraform/CloudFormation)")
    print("4. Source Code")
    
    choices = input("Your choice: ").split(',')

    for choice in choices:
        choice = choice.strip()
        if choice == '1':
            path = get_file_path("UML/PlantUML")
            if path:
                parse_and_add("UML/PlantUML", parse_uml, path, system_model)
        elif choice == '2':
            path = get_file_path("OpenAPI/Swagger")
            if path:
                parse_and_add("OpenAPI/Swagger", parse_openapi, path, system_model)
        elif choice == '3':
            path = get_file_path("IaC (Terraform/CloudFormation)")
            if path:
                parse_and_add("IaC", parse_iac, path, system_model)
        elif choice == '4':
            path = get_file_path("Source Code")
            if path:
                parse_and_add("Source Code", parse_source_code, path, system_model)
        else:
            print(f"Invalid choice: {choice}")

    # Run threat engine
    engine = ThreatEngine()
    threats = engine.analyze(system_model)

    print("\n=== Threat Report ===")
    for t in threats:
        print(f"{t['component']} | {t['stride']} | DREAD: {t['dread_score']} | Mitigation: {t['suggested_mitigation']}")

if __name__ == "__main__":
    main()
