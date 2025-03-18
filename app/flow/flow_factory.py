from typing import Dict, List, Union

from app.agent.base import BaseAgent
from app.flow.base import BaseFlow, FlowType
from app.flow.planning import PlanningFlow
from app.flow.pentest import PenTestFlow


# Erweitere den FlowType um PENTEST
class FlowType(FlowType):  # type: ignore
    """Erweiterte Aufzählung der verfügbaren Flow-Typen."""
    
    PLANNING = "planning"
    PENTEST = "pentest"


class FlowFactory:
    """Factory for creating different types of flows with support for multiple agents"""

    @staticmethod
    def create_flow(
        flow_type: FlowType,
        agents: Union[BaseAgent, List[BaseAgent], Dict[str, BaseAgent]],
        **kwargs,
    ) -> BaseFlow:
        flows = {
            FlowType.PLANNING: PlanningFlow,
            FlowType.PENTEST: PenTestFlow,  # Füge PenTestFlow hinzu
        }

        flow_class = flows.get(flow_type)
        if not flow_class:
            raise ValueError(f"Unknown flow type: {flow_type}")

        return flow_class(agents, **kwargs)
