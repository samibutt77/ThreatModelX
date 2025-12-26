import xml.etree.ElementTree as ET
import html
import urllib.parse
import os
import re

from models import SystemModel, Component, DataFlow, DataStore


def decode_value(value):
    """Decode HTML/XML/URL encoded draw.io cell values."""
    if not value:
        return ""
    value = html.unescape(value)
    value = urllib.parse.unquote(value)
    return value.strip()


def parse_uml(file_path: str) -> SystemModel:
    """
    UNIVERSAL UML PARSER (Draw.io + PlantUML)
    Detects file type automatically:
    - .drawio/.xml  => Draw.io XML parser
    - .uml/.puml/.plantuml/.txt => PlantUML parser

    Returns SystemModel with:
      - Components
      - Data Stores
      - Data Flows
      - Trust Boundaries
    """

    system_model = SystemModel()

    ext = os.path.splitext(file_path)[1].lower()

    # -------------------------------------------------------
    # 1️⃣ IF FILE IS PLANTUML (.uml / .puml / .plantuml)
    # -------------------------------------------------------
    if ext in [".uml", ".puml", ".plantuml", ".txt"]:
        print("[INFO] Parsing PlantUML file...")

        with open(file_path, "r") as f:
            content = f.read()

        lines = [line.strip() for line in content.splitlines() if line.strip()]

        # Regex for PlantUML
        class_pattern = re.compile(r'class\s+(\w+)')
        entity_pattern = re.compile(r'entity\s+(\w+)')
        actor_pattern = re.compile(r'actor\s+(\w+)')
        usecase_pattern = re.compile(r'usecase\s+(\w+)')
        flow_pattern = re.compile(r'(\w+)\s*-->\s*(\w+)')
        boundary_pattern = re.compile(r'package\s+(\w+)')

        current_boundary = None

        for line in lines:

            # Trust boundary
            b = boundary_pattern.search(line)
            if b:
                current_boundary = b.group(1)
                continue

            # Components
            c = class_pattern.search(line)
            if c:
                comp = Component(id=c.group(1), type="component", boundary=current_boundary)
                system_model.add_component(comp)
                continue

            # Data stores
            d = entity_pattern.search(line)
            if d:
                ds = DataStore(id=d.group(1), type="datastore", boundary=current_boundary)
                system_model.add_datastore(ds)
                continue

            # Actor
            a = actor_pattern.search(line)
            if a:
                actor = Component(id=a.group(1), type="actor", boundary=current_boundary)
                system_model.add_component(actor)
                continue

            # Use case
            u = usecase_pattern.search(line)
            if u:
                uc = Component(id=u.group(1), type="usecase", boundary=current_boundary)
                system_model.add_component(uc)
                continue

            # Data flow
            f = flow_pattern.search(line)
            if f:
                system_model.add_dataflow(DataFlow(source=f.group(1), target=f.group(2)))
                continue

        return system_model

    # -------------------------------------------------------
    # 2️⃣ OTHERWISE: PARSE AS DRAW.IO XML
    # -------------------------------------------------------
    print("[INFO] Parsing Draw.io XML file...")

    tree = ET.parse(file_path)
    root = tree.getroot()

    id_to_name = {}
    id_to_type = {}

    # FIRST PASS: detect nodes
    for cell in root.iter("mxCell"):
        cell_id = cell.get("id")
        value = decode_value(cell.get("value"))
        style = cell.get("style", "")

        # Skip empty labels unless edge
        if not value and "edge=1" not in style:
            continue

        # Trust boundaries
        if "swimlane" in style or "container" in style or "group" in style:
            id_to_name[cell_id] = value
            id_to_type[cell_id] = "boundary"
            continue

        # Components
        if "shape=umlClass" in style or "rounded=1" in style:
            comp = Component(id=value, type="component")
            system_model.add_component(comp)
            id_to_name[cell_id] = value
            id_to_type[cell_id] = "component"
            continue

        # Data stores
        if "shape=cylinder" in style or "datastore" in style:
            ds = DataStore(id=value, type="datastore")
            system_model.add_datastore(ds)
            id_to_name[cell_id] = value
            id_to_type[cell_id] = "datastore"
            continue

        # Actors
        if "shape=umlActor" in style:
            actor = Component(id=value, type="actor")
            system_model.add_component(actor)
            id_to_name[cell_id] = value
            id_to_type[cell_id] = "actor"
            continue

        # Use cases
        if "ellipse" in style or "usecase" in style:
            usecase = Component(id=value, type="usecase")
            system_model.add_component(usecase)
            id_to_name[cell_id] = value
            id_to_type[cell_id] = "usecase"
            continue

    # SECOND PASS: detect edges
    for cell in root.iter("mxCell"):
        if cell.get("edge") == "1":
            src = id_to_name.get(cell.get("source"))
            tgt = id_to_name.get(cell.get("target"))
            if src and tgt:
                system_model.add_dataflow(DataFlow(source=src, target=tgt))

    return system_model
