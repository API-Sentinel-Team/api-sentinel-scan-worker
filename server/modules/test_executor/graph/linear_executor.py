from typing import Dict, Any, List
from server.modules.test_executor.graph.base_executor import BaseGraphExecutor
from server.modules.test_executor.graph.graph import Graph, Node
import logging

logger = logging.getLogger(__name__)

class LinearGraphExecutor(BaseGraphExecutor):
    async def execute(self, graph: Graph, initial_context: Dict[str, Any], run_node_callback) -> Dict[str, Any]:
        values_map = initial_context.get("values_map", {}).copy()
        
        # Simple topological sort for linear execution (assuming DAG)
        ordered_nodes = self._topological_sort(graph)
        
        for node_id in ordered_nodes:
            node = graph.nodes[node_id]
            logger.info(f"Executing node: {node_id} ({node.type})")
            
            try:
                node.status = "running"
                # Call execute_node which uses the runner callback
                result = await self.execute_node(node, values_map, run_node_callback)
                node.result = result
                node.status = "completed"
            except Exception as e:
                node.status = "failed"
                node.error = str(e)
                logger.error(f"Node {node_id} failed: {e}")
                break # Stop linear execution on failure
                
        return values_map

    def _topological_sort(self, graph: Graph) -> List[str]:
        # Basic Kahn's algorithm or similar
        visited = []
        stack = []
        
        def visit(n_id):
            if n_id in stack: return
            if n_id in visited: return
            stack.append(n_id)
            for m_id in graph.get_successors(n_id):
                visit(m_id)
            stack.pop()
            visited.insert(0, n_id)

        # Start from nodes with no predecessors
        roots = [n_id for n_id, n in graph.nodes.items() if not n.depends_on]
        for root in roots:
            visit(root)
            
        return visited[::-1] # Reverse to get execution order
