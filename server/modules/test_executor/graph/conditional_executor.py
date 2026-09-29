from typing import Dict, Any, List
from server.modules.test_executor.graph.base_executor import BaseGraphExecutor
from server.modules.test_executor.graph.graph import Graph, Node
import logging

logger = logging.getLogger(__name__)

class ConditionalGraphExecutor(BaseGraphExecutor):
    async def execute(self, graph: Graph, initial_context: Dict[str, Any], run_node_callback) -> Dict[str, Any]:
        context = initial_context.copy()
        
        # Start from root nodes
        current_node_ids = [n_id for n_id, n in graph.nodes.items() if not n.depends_on]
        
        while current_node_ids:
            next_node_ids = []
            for n_id in current_node_ids:
                node = graph.nodes[n_id]
                node.status = "running"
                
                result = await self.execute_node(node, context, run_node_callback)
                node.result = result
                node.status = "completed"
                
                # Check outgoing edges for conditions
                for edge in graph.edges:
                    if edge.source == n_id:
                        if self._evaluate_condition(edge.condition, context):
                            next_node_ids.append(edge.target)
                        else:
                            graph.nodes[edge.target].status = "skipped"
                            
            current_node_ids = list(set(next_node_ids))
            
        return context

    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        if not condition: return True
        
        try:
            # Basic eval - in production we'd use a safer DSL evaluator
            # but Akto style often uses status code or existence checks
            # Example: "response.status == 200" or "step1.user_id != null"
            return eval(condition, {"__builtins__": {}}, context)
        except Exception as e:
            logger.error(f"Error evaluating condition '{condition}': {e}")
            return False
