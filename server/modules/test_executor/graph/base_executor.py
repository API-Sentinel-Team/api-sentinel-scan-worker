import abc
from typing import Dict, Any, List
from server.modules.test_executor.graph.graph import Graph, Node, NodeType
from server.modules.test_executor.context_manager import ContextManager

class BaseGraphExecutor(abc.ABC):
    def __init__(self, context_manager: ContextManager):
        self.context_manager = context_manager
        self.results = {}

    @abc.abstractmethod
    async def execute(self, graph: Graph, initial_context: Dict[str, Any], run_node_callback) -> Dict[str, Any]:
        pass

    async def execute_node(self, node: Node, values_map: Dict[str, Any], run_node_callback) -> Any:
        # Resolve variables in node data using the current values_map
        resolved_data = self.context_manager.substitute_variables(node.data, values_map)
        
        # Call the actual execution logic
        result = await run_node_callback(node, resolved_data, values_map)
        
        # Update values_map with extraction rules if any (e.g., extracting a token from response)
        if 'extract' in node.data:
            extracted = self.context_manager.extract_from_response(result, node.data['extract'])
            values_map.update(extracted)
            
        return result
