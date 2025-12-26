# diagram_generator.py
from graphviz import Digraph
import os

def sanitize(name):
    return name.replace(" ", "_").replace("-", "_").replace("/", "_")

def generate_annotated_diagram(system_model, threats, out_dir="uploads"):
    import graphviz, os
    os.makedirs(out_dir, exist_ok=True)

    dot = graphviz.Digraph(format="png")

    # Build a set of risky components/flows
    risky_ids = set(t['component'] for t in threats if t['dread_score'] > 0)  # you can set a threshold if desired

    # Add components
    for c in system_model.components:
        if c.id in risky_ids:
            dot.node(c.id, label=c.id, shape="box", color="red", style="filled", fillcolor="#ffcccc")
        else:
            dot.node(c.id, label=c.id, shape="box")

    # Add datastores
    for d in system_model.datastores:
        if d.id in risky_ids:
            dot.node(d.id, label=d.id, shape="cylinder", color="red", style="filled", fillcolor="#ffcccc")
        else:
            dot.node(d.id, label=d.id, shape="cylinder")

    # Add dataflows
    for f in system_model.dataflows:
        flow_id = f"flow_{f.source}_to_{f.target}"
        if flow_id in risky_ids:
            dot.edge(f.source, f.target, label=flow_id, color="red")
        else:
            dot.edge(f.source, f.target, label=flow_id)

    # Output file
    output_file = os.path.join(out_dir, "annotated_diagram")
    png_path = dot.render(filename=output_file, cleanup=True)
    return os.path.basename(png_path)

