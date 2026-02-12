"""
Specific Agent Implementations - Different agent types for Phase 2

Provides:
- CoordinatorAgent - Orchestrates other agents
- ResearcherAgent - Analyzes and researches
- ExecutorAgent - Executes tasks
- ValidatorAgent - Validates results
"""

from typing import List, Optional, Dict, Any
from .base import BaseAgent, AgentType, AgentCapability


class CoordinatorAgent(BaseAgent):
    """
    Coordinator Agent - Orchestrates tasks across multiple agents

    Responsibilities:
    - Break down complex tasks
    - Delegate to specialized agents
    - Monitor task progress
    - Aggregate results
    """

    def __init__(self, agent_id: Optional[str] = None, agent_name: str = "Coordinator"):
        """Initialize coordinator agent"""
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.COORDINATOR,
            agent_name=agent_name,
            description="Orchestrates and coordinates tasks across specialized agents",
            capabilities=[
                AgentCapability.ORCHESTRATE,
                AgentCapability.DELEGATE,
                AgentCapability.READ,
                AgentCapability.WRITE,
            ],
        )
        self._delegated_tasks: Dict[str, Dict[str, Any]] = {}
        self._task_results: Dict[str, Any] = {}

    def create_task(
        self,
        task_id: str,
        description: str,
        subtasks: List[Dict[str, Any]],
    ) -> None:
        """
        Create a complex task with subtasks

        Args:
            task_id: Unique task identifier
            description: Task description
            subtasks: List of subtasks to delegate
        """
        self._delegated_tasks[task_id] = {
            "description": description,
            "subtasks": subtasks,
            "status": "active",
            "results": {},
        }

    def get_delegated_tasks(self) -> Dict[str, Dict[str, Any]]:
        """Get all delegated tasks"""
        return self._delegated_tasks.copy()

    def store_result(self, task_id: str, subtask_id: str, result: Any) -> None:
        """Store result from a subtask"""
        if task_id in self._delegated_tasks:
            self._delegated_tasks[task_id]["results"][subtask_id] = result

    def get_results(self, task_id: str) -> Dict[str, Any]:
        """Get all results for a task"""
        if task_id in self._delegated_tasks:
            return self._delegated_tasks[task_id]["results"]
        return {}

    def complete_task(self, task_id: str) -> bool:
        """Mark a task as completed"""
        if task_id in self._delegated_tasks:
            self._delegated_tasks[task_id]["status"] = "completed"
            return True
        return False

    def __str__(self) -> str:
        """String representation"""
        return f"CoordinatorAgent({self.agent_id}, tasks={len(self._delegated_tasks)})"


class ResearcherAgent(BaseAgent):
    """
    Researcher Agent - Analyzes and researches information

    Responsibilities:
    - Gather information
    - Perform analysis
    - Generate reports
    - Validate data quality
    """

    def __init__(self, agent_id: Optional[str] = None, agent_name: str = "Researcher"):
        """Initialize researcher agent"""
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.RESEARCHER,
            agent_name=agent_name,
            description="Analyzes and researches information from various sources",
            capabilities=[
                AgentCapability.READ,
                AgentCapability.ANALYZE,
                AgentCapability.WRITE,
                AgentCapability.DELEGATE,
            ],
        )
        self._research_projects: Dict[str, Dict[str, Any]] = {}
        self._findings: Dict[str, List[str]] = {}

    def start_research(
        self,
        project_id: str,
        topic: str,
        sources: List[str],
    ) -> None:
        """
        Start a new research project

        Args:
            project_id: Unique project identifier
            topic: Topic to research
            sources: List of sources to use
        """
        self._research_projects[project_id] = {
            "topic": topic,
            "sources": sources,
            "status": "active",
            "findings": [],
        }

    def add_finding(self, project_id: str, finding: str) -> None:
        """Add a finding to a research project"""
        if project_id in self._research_projects:
            self._research_projects[project_id]["findings"].append(finding)
            if project_id not in self._findings:
                self._findings[project_id] = []
            self._findings[project_id].append(finding)

    def get_findings(self, project_id: str) -> List[str]:
        """Get findings from a research project"""
        return self._findings.get(project_id, []).copy()

    def complete_research(self, project_id: str) -> bool:
        """Mark research as completed"""
        if project_id in self._research_projects:
            self._research_projects[project_id]["status"] = "completed"
            return True
        return False

    def __str__(self) -> str:
        """String representation"""
        return f"ResearcherAgent({self.agent_id}, projects={len(self._research_projects)})"


class ExecutorAgent(BaseAgent):
    """
    Executor Agent - Executes tasks and actions

    Responsibilities:
    - Execute assigned tasks
    - Handle data processing
    - Perform actions
    - Report execution status
    """

    def __init__(self, agent_id: Optional[str] = None, agent_name: str = "Executor"):
        """Initialize executor agent"""
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.EXECUTOR,
            agent_name=agent_name,
            description="Executes tasks and performs data processing operations",
            capabilities=[
                AgentCapability.READ,
                AgentCapability.WRITE,
                AgentCapability.EXECUTE,
            ],
        )
        self._task_queue: Dict[str, Dict[str, Any]] = {}
        self._execution_results: Dict[str, Any] = {}

    def queue_task(
        self,
        task_id: str,
        action: str,
        parameters: Dict[str, Any],
    ) -> None:
        """
        Queue a task for execution

        Args:
            task_id: Unique task identifier
            action: Action to execute
            parameters: Parameters for the action
        """
        self._task_queue[task_id] = {
            "action": action,
            "parameters": parameters,
            "status": "queued",
        }

    def execute_task(self, task_id: str) -> bool:
        """
        Execute a queued task

        Args:
            task_id: Task to execute

        Returns:
            True if execution started successfully
        """
        if task_id not in self._task_queue:
            return False

        self._task_queue[task_id]["status"] = "executing"
        return True

    def complete_task(self, task_id: str, result: Any) -> bool:
        """
        Mark a task as completed with result

        Args:
            task_id: Task that completed
            result: Result data

        Returns:
            True if successful
        """
        if task_id not in self._task_queue:
            return False

        self._task_queue[task_id]["status"] = "completed"
        self._execution_results[task_id] = result
        return True

    def get_result(self, task_id: str) -> Optional[Any]:
        """Get the result of an executed task"""
        return self._execution_results.get(task_id)

    def __str__(self) -> str:
        """String representation"""
        return f"ExecutorAgent({self.agent_id}, queued_tasks={len(self._task_queue)})"


class ValidatorAgent(BaseAgent):
    """
    Validator Agent - Validates results and quality

    Responsibilities:
    - Validate results
    - Check data quality
    - Perform verification
    - Report validation status
    """

    def __init__(self, agent_id: Optional[str] = None, agent_name: str = "Validator"):
        """Initialize validator agent"""
        super().__init__(
            agent_id=agent_id,
            agent_type=AgentType.VALIDATOR,
            agent_name=agent_name,
            description="Validates results and ensures quality standards",
            capabilities=[
                AgentCapability.READ,
                AgentCapability.VALIDATE,
            ],
        )
        self._validation_rules: Dict[str, List[str]] = {}
        self._validation_results: Dict[str, Dict[str, Any]] = {}

    def add_validation_rule(self, result_type: str, rule: str) -> None:
        """
        Add a validation rule

        Args:
            result_type: Type of result this rule applies to
            rule: The validation rule
        """
        if result_type not in self._validation_rules:
            self._validation_rules[result_type] = []
        self._validation_rules[result_type].append(rule)

    def validate_result(
        self,
        result_id: str,
        result_type: str,
        result_data: Any,
    ) -> bool:
        """
        Validate a result

        Args:
            result_id: Unique result identifier
            result_type: Type of result
            result_data: The result to validate

        Returns:
            True if validation passes, False otherwise
        """
        rules = self._validation_rules.get(result_type, [])

        # Simple validation: check if result is not empty
        is_valid = result_data is not None

        self._validation_results[result_id] = {
            "result_type": result_type,
            "is_valid": is_valid,
            "rules_checked": len(rules),
            "data_sample": str(result_data)[:100],
        }

        return is_valid

    def get_validation_status(self, result_id: str) -> Optional[Dict[str, Any]]:
        """Get validation status for a result"""
        return self._validation_results.get(result_id)

    def __str__(self) -> str:
        """String representation"""
        return f"ValidatorAgent({self.agent_id}, validations={len(self._validation_results)})"
