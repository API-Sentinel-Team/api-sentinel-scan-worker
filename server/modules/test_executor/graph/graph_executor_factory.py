"""
Factory for graph executors — selects linear or parallel based on execute.type.
"""


class LinearExecutor:
    """Executes nodes in topological order (linear chain)."""

    def __init__(self, context_manager):
        self.ctx = context_manager

    async def execute(self, graph, initial_data: dict, node_callback) -> None:
        order = graph.topological_order()
        for node_id in order:
            node = graph.nodes[node_id]
            resolved = self.ctx.substitute_recursive(node.data)
            response_data = await node_callback(node, resolved, self.ctx.store)
            if response_data:
                # Extract variables from response for downstream nodes
                extract_rules = node.data.get("extract", [])
                if extract_rules:
                    self.ctx.extract_from_response(response_data, extract_rules)


class MultiExecutor:
    """
    Expands wordList values and runs a separate request per value.
    Used for execute.type = multiple.
    """

    def __init__(self, context_manager):
        self.ctx = context_manager

    async def execute(self, graph, initial_data: dict, node_callback) -> None:
        order = graph.topological_order()
        for node_id in order:
            node = graph.nodes[node_id]
            resolved = self.ctx.substitute_recursive(node.data)
            await node_callback(node, resolved, self.ctx.store)


class GraphExecutorFactory:
    @staticmethod
    def get_executor(execute_type: str, context_manager):
        execute_type = (execute_type or "linear").lower()
        if execute_type == "multiple":
            return MultiExecutor(context_manager)
        # single / linear / default
        return LinearExecutor(context_manager)
