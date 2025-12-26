from UMLParser import parse_plantuml
from openAPI_Parser import parse_openapi
from iac_Parser import parse_iac
from source_code_Parser import parse_source_code
from models import SystemModel
from threatEngine import ThreatEngine


system_model = SystemModel()

# ========================
#  Parse UML file
# ========================
uml_file_path = "C:/Users/Ashfaq Ahmed/Desktop/SSD_project_2/example.uml"
uml_model = parse_plantuml(uml_file_path)

print("=== UML Parser Output ===")
print("Components:")
for c in uml_model.components:
    boundary = getattr(c, "boundary", None)
    if boundary:
        print(f"- {c.id} (Boundary: {boundary})")
    else:
        print(f"- {c.id} ({c.type})")

print("Data Stores:")
for d in uml_model.datastores:
    boundary = getattr(d, "boundary", None)
    if boundary:
        print(f"- {d.id} (Boundary: {boundary})")
    else:
        print(f"- {d.id} ({d.type})")

print("Data Flows:")
for f in uml_model.dataflows:
    print(f"- {f.source} -> {f.target}")

print("\n\n")

# ========================
#  Parse OpenAPI file
# ========================
openapi_file_path = "C:/Users/Ashfaq Ahmed/Desktop/SSD_project_2/example.yaml"
api_model = parse_openapi(openapi_file_path)

print("=== OpenAPI Parser Output ===")
print("Components:")
for c in api_model.components:
    boundary = getattr(c, "boundary", None)
    if boundary:
        print(f"- {c.id} (Boundary: {boundary})")
    else:
        print(f"- {c.id} ({c.type})")

print("Data Stores:")
for d in api_model.datastores:
    boundary = getattr(d, "boundary", None)
    if boundary:
        print(f"- {d.id} (Boundary: {boundary})")
    else:
        print(f"- {d.id} ({d.type})")

print("Data Flows:")
for f in api_model.dataflows:
    print(f"- {f.source} -> {f.target}")

print("\n\n")

# ========================
#  Parse IaC file
# ========================
iac_file_path = "C:/Users/Ashfaq Ahmed/Desktop/SSD_project_2/example.tf"
iac_model = parse_iac(iac_file_path)

print("=== IaC Parser Output ===")
print("Components:")
for c in iac_model.components:
    boundary = getattr(c, "boundary", None)
    if boundary:
        print(f"- {c.id} (Boundary: {boundary})")
    else:
        print(f"- {c.id} ({c.type})")

print("Data Stores:")
for d in iac_model.datastores:
    boundary = getattr(d, "boundary", None)
    if boundary:
        print(f"- {d.id} (Boundary: {boundary})")
    else:
        print(f"- {d.id} ({d.type})")

print("Data Flows:")
for f in iac_model.dataflows:
    print(f"- {f.source} -> {f.target}")


print("\n\n")

# ========================
#  Parse source code file
# ========================

source_code_file_path = "C:/Users/Ashfaq Ahmed/Desktop/SSD_project_2/test_app.py"
model = parse_source_code(source_code_file_path)

print("=== Source_Code Parser Output ===")
print("Components:")
for c in model.components:
    print(f"- {c.id} ({c.type})")

print("\nData Stores:")
for d in model.datastores:
    print(f"- {d.id} ({d.type})")

print("\nData Flows:")
for f in model.dataflows:
    print(f"- {f.source} -> {f.target}")



# ========================
#  Threat Engine Code
# ========================

# Add UML
for c in uml_model.components:
    system_model.add_component(c)
for d in uml_model.datastores:
    system_model.add_datastore(d)
for f in uml_model.dataflows:
    system_model.add_dataflow(f)

# Add OpenAPI
for c in api_model.components:
    system_model.add_component(c)
for d in api_model.datastores:
    system_model.add_datastore(d)
for f in api_model.dataflows:
    system_model.add_dataflow(f)

# Add IaC
for c in iac_model.components:
    system_model.add_component(c)
for d in iac_model.datastores:
    system_model.add_datastore(d)
for f in iac_model.dataflows:
    system_model.add_dataflow(f)

# Add Source Code
for c in model.components:
    system_model.add_component(c)
for d in model.datastores:
    system_model.add_datastore(d)
for f in model.dataflows:
    system_model.add_dataflow(f)

engine = ThreatEngine()
threats = engine.analyze(system_model)

print("\n=== Threat Report ===")
for t in threats:
    print(f"{t['component']} | {t['stride']} | DREAD: {t['dread_score']} | Mitigation: {t['suggested_mitigation']}")