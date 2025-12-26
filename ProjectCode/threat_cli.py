import json
import sys
import os

from threatEngine import ThreatEngine
from models import SystemModel
from UMLParser import parse_uml
from openAPI_Parser import parse_openapi
from iac_Parser import parse_iac
from source_code_Parser import parse_source_code
from diagram_generator import generate_annotated_diagram


def parse_file(file_path, parser_type, system_model):
    parser_map = {
        "uml": parse_uml,
        "openapi": parse_openapi,
        "iac": parse_iac,
        "source": parse_source_code
    }

    if parser_type not in parser_map:
        print(f"Unknown parser type: {parser_type}")
        sys.exit(1)

    parser_func = parser_map[parser_type]
    parsed = parser_func(file_path)

    # Merge results into system model without touching your original code
    if hasattr(parsed, "components"):
        for c in parsed.components:
            system_model.add_component(c)

    if hasattr(parsed, "datastores"):
        for d in parsed.datastores:
            system_model.add_datastore(d)

    if hasattr(parsed, "dataflows"):
        for f in parsed.dataflows:
            system_model.add_dataflow(f)


def main():
    if len(sys.argv) < 3:
        print("Usage: python threat_cli.py <parser_type> <file>")
        print("Example: python threat_cli.py uml design.uml")
        sys.exit(1)

    parser_type = sys.argv[1]     # uml / openapi / iac / source
    file_path = sys.argv[2]

    system_model = SystemModel()

    # Use your existing parsers
    parse_file(file_path, parser_type, system_model)

    # Use your existing threat engine
    engine = ThreatEngine()      
    threats = engine.analyze(system_model)

    # Output folder for CI/CD
    os.makedirs("pipeline_output", exist_ok=True)

    # Save threat report
    with open("pipeline_output/threat_report.json", "w") as f:
        json.dump(threats, f, indent=2)

    # Save annotated diagram using your existing diagram generator
    diagram_path = generate_annotated_diagram(
        system_model, 
        threats, 
        out_dir="pipeline_output"
    )

    print("Threat analysis completed.")
    print("Report saved to: pipeline_output/threat_report.json")
    print("Diagram saved to:", diagram_path)


if __name__ == "__main__":
    main()
