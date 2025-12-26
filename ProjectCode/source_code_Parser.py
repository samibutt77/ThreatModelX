import ast
from models import SystemModel, Component, DataFlow, DataStore

class CodeVisitor(ast.NodeVisitor):
    """
    Visits Python AST nodes to extract components, data stores, and function calls.
    """
    def __init__(self):
        self.system_model = SystemModel()
        self.current_class = None

    def visit_ClassDef(self, node):
        # Treat every class as a component
        comp = Component(id=node.name, type="class")
        self.system_model.add_component(comp)

        # Optionally treat classes with 'Model' or 'DB' in name as data stores
        if "Model" in node.name or "DB" in node.name:
            ds = DataStore(id=node.name, type="datastore")
            self.system_model.add_datastore(ds)

        # Keep track of current class for function parsing
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = None

    def visit_FunctionDef(self, node):
        # Treat functions as components
        func_name = f"{self.current_class}.{node.name}" if self.current_class else node.name
        comp = Component(id=func_name, type="function")
        self.system_model.add_component(comp)

        # Parse function calls to create data flows
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Attribute):
                    target = f"{n.func.value.id}.{n.func.attr}" if hasattr(n.func.value, 'id') else n.func.attr
                elif isinstance(n.func, ast.Name):
                    target = n.func.id
                else:
                    target = None
                if target:
                    df = DataFlow(source=func_name, target=target)
                    self.system_model.add_dataflow(df)

        self.generic_visit(node)

def parse_source_code(file_path: str) -> SystemModel:
    """
    Parses a Python source code file and returns a SystemModel.
    """
    with open(file_path, "r") as f:
        source = f.read()

    tree = ast.parse(source)
    visitor = CodeVisitor()
    visitor.visit(tree)
    return visitor.system_model
