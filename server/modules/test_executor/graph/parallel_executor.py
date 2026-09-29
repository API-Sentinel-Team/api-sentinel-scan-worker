import asyncio
from typing import Dict, Any, List, Set
from server.modules.test_executor.graph.base_executor import BaseGraphExecutor
from server.modules.test_executor.graph.graph import Graph, Node
import logging

logger = logging.getLogger(__name__)

class ParallelGraphExecutor(BaseGraphExecutor):
    async def execute(self, graph: Graph, initial_context: Dict[str, Any], run_node_callback) -> Dict[str, Any]:
        context = initial_context.copy()
        pending_nodes: Set[str] = set(graph.nodes.keys())
        completed_nodes: Set[str] = set()
        
        while pending_nodes:
            # Find nodes that have all dependencies met
            ready_nodes = [
                n_id for n_id in pending_nodes 
                if all(dep in completed_nodes for dep in graph.nodes[n_id].depends_on)
            ]
            
            if not ready_nodes:
                if pending_nodes:
                    logger.error("Deadlock detected in graph execution!")
                break
                
            # Execute ready nodes in parallel
            tasks = [self._execute_wrapper(graph.nodes[n_id], context, run_node_callback) for n_id in ready_nodes]
            await asyncio.gather(*tasks)
            
            # Update state
            for n_id in ready_nodes:
                pending_nodes.remove(n_id)
                completed_nodes.add(n_id)
                
        return context

    async def _execute_wrapper(self, node: Node, context: Dict[str, Any], run_node_callback):
        node.status = "running"
        try:
            result = await self.execute_node(node, context, run_node_callback)
            node.result = result
            node.status = "completed"
        except Exception as e:
            node.status = "failed"
            node.error = str(e)
            logger.error(f"Parallel node {node.id} failed: {e}")
