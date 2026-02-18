"""
ICARUS-X AI Engine
==================
AI-powered assistant for command suggestions, explanations, and reporting.
Powered by Cerebras - World's fastest AI inference.
"""

import asyncio
import os
from typing import Optional

from utils.config import IcarusConfig
from utils.logger import get_logger


class AIEngine:
    """
    AI-powered pentesting assistant powered by Cerebras.
    
    Features:
    - Command suggestions based on context
    - CVE/vulnerability explanations
    - Finding analysis and remediation
    - Report summarization
    - Real-time AI responses (up to 3000 tokens/s)
    """
    
    def __init__(self, config: IcarusConfig):
        self.config = config
        self.logger = get_logger()
        self.client = None
        self._initialized = False
    
    async def _ensure_initialized(self):
        """Initialize AI client on first use."""
        if self._initialized:
            return
        
        api_key = self.config.ai.api_key
        if not api_key:
            raise ValueError(
                "AI API key not configured. Set ICARUS_AI_API_KEY or CEREBRAS_API_KEY environment variable.\n"
                "Get free API key from: https://inference.cerebras.ai/"
            )
        
        provider = self.config.ai.provider
        
        if provider == "cerebras":
            from cerebras.cloud.sdk import Cerebras
            self.client = Cerebras(api_key=api_key)
            
            # Validate model
            if self.config.ai.model not in self.config.ai.available_models:
                self.logger.warning(
                    f"Unknown model: {self.config.ai.model}. Using default: llama3.1-8b"
                )
                self.config.ai.model = "llama3.1-8b"
            
            model_info = self.config.ai.available_models[self.config.ai.model]
            self.logger.info(
                f"AI engine initialized with Cerebras {self.config.ai.model} "
                f"({model_info['params']}, {model_info['speed']})"
            )
        else:
            raise ValueError(f"Unsupported AI provider: {provider}. Use 'cerebras'.")
        
        self._initialized = True
    
    async def ask(self, query: str) -> str:
        """
        Ask a general question to the AI.
        
        Args:
            query: User's question
            
        Returns:
            AI response
        """
        await self._ensure_initialized()
        
        prompt = f"""You are ICARUS-X, an AI assistant specialized in penetration testing and cybersecurity.

Question: {query}

Provide a clear, well-structured response using markdown:
- Use **bold** for important terms
- Use `code` for commands, tools, or technical terms
- Use numbered lists for steps
- Use bullet points for options/alternatives
- Use code blocks with ```bash for command examples

Be practical and actionable. Assume authorized penetration testing context."""
        
        return await self._generate(prompt)
    
    async def suggest_commands(self, goal: str, context: Optional[dict] = None) -> str:
        """
        Suggest commands to achieve a pentesting goal.
        
        Args:
            goal: What the user wants to achieve
            context: Optional context from a run (target, findings, etc.)
            
        Returns:
            Suggested commands with explanations
        """
        await self._ensure_initialized()
        
        context_str = ""
        if context:
            context_str = f"""
Context from current scan:
- Target: {context.get('target', 'Unknown')}
- Phase status: {context.get('phases', {})}
- Known findings: {', '.join(context.get('findings', [])[:5])}
"""
        
        prompt = f"""You are ICARUS-X, an AI pentesting assistant.

Goal: {goal}
{context_str}

Suggest 3-5 specific commands to achieve this goal. Format EXACTLY like this:

### Command 1: [Brief Description]
```bash
[exact command here]
```
**What it does:** [explanation]

**Expected output:** [what to expect]

---

### Command 2: [Brief Description]
...

Use common tools like nmap, netcat, curl, hydra, sqlmap, gobuster, nikto, etc.
Keep explanations concise. Always use code blocks for commands."""
        
        return await self._generate(prompt)
    
    async def explain(self, topic: str) -> str:
        """
        Explain a CVE, vulnerability, or security concept.
        
        Args:
            topic: CVE ID, vulnerability name, or concept
            
        Returns:
            Detailed explanation
        """
        await self._ensure_initialized()
        
        prompt = f"""You are ICARUS-X, an AI cybersecurity expert.

Explain: **{topic}**

Structure your response with these exact headers:

## Overview
[What is it? Brief explanation]

## Impact
[Security impact - what can attackers do?]

## Affected Systems
[List vulnerable systems/versions with bullet points]

## Detection
[How to detect - include specific commands if applicable]
```bash
# detection command example
```

## Remediation
[How to fix - prioritized steps]

Be accurate, technical, and include relevant command examples where helpful."""
        
        return await self._generate(prompt)
    
    async def analyze_finding(self, finding_data: dict) -> str:
        """
        Analyze a security finding and provide recommendations.
        
        Args:
            finding_data: Finding details (title, description, affected_asset, etc.)
            
        Returns:
            Analysis and recommendations
        """
        await self._ensure_initialized()
        
        prompt = f"""You are ICARUS-X, an AI pentesting assistant.

Analyze this security finding:
- Title: {finding_data.get('title', 'Unknown')}
- Severity: {finding_data.get('severity', 'Unknown')}
- Affected Asset: {finding_data.get('affected_asset', 'Unknown')}
- Description: {finding_data.get('description', 'No description')}

Provide:
1. **Risk Assessment**: Explain the real-world risk
2. **Exploitation Path**: How could an attacker exploit this?
3. **Recommended Tests**: What follow-up tests should be done?
4. **Remediation Priority**: Immediate, short-term, long-term actions

Be specific and actionable."""
        
        return await self._generate(prompt)
    
    async def summarize_findings(self, findings: list[dict]) -> str:
        """
        Generate an executive summary of findings.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Executive summary
        """
        await self._ensure_initialized()
        
        findings_text = "\n".join([
            f"- [{f.get('severity', 'INFO')}] {f.get('title', 'Unknown')}"
            for f in findings[:20]
        ])
        
        prompt = f"""You are ICARUS-X, writing an executive summary for a penetration test report.

Findings:
{findings_text}

Write a 2-3 paragraph executive summary that:
1. Summarizes the overall security posture
2. Highlights the most critical issues
3. Provides high-level recommendations

Write for a non-technical audience (executives, managers)."""
        
        return await self._generate(prompt)
    
    async def _generate(self, prompt: str) -> str:
        """Generate response from AI model using Cerebras."""
        try:
            if self.config.ai.provider == "cerebras":
                response = await asyncio.to_thread(
                    self.client.chat.completions.create,
                    messages=[
                        {
                            "role": "user",
                            "content": prompt,
                        }
                    ],
                    model=self.config.ai.model,
                    max_tokens=self.config.ai.max_tokens,
                    temperature=self.config.ai.temperature,
                )
                return response.choices[0].message.content
            else:
                raise ValueError(f"Unsupported provider: {self.config.ai.provider}")
            
        except Exception as e:
            self.logger.error(f"AI generation failed: {e}")
            return (
                f"AI generation failed: {str(e)}\n\n"
                f"Please check your CEREBRAS_API_KEY and try again.\n"
                f"Get free API key from: https://inference.cerebras.ai/"
            )
