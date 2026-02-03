"""
ICARUS-X AI Engine
==================
AI-powered assistant for command suggestions, explanations, and reporting.
"""

import asyncio
import os
from typing import Optional

from utils.config import IcarusConfig
from utils.logger import get_logger


class AIEngine:
    """
    AI-powered pentesting assistant.
    
    Features:
    - Command suggestions based on context
    - CVE/vulnerability explanations
    - Finding analysis and remediation
    - Report summarization
    """
    
    def __init__(self, config: IcarusConfig):
        self.config = config
        self.logger = get_logger()
        self.model = None
        self._initialized = False
    
    async def _ensure_initialized(self):
        """Initialize AI client on first use."""
        if self._initialized:
            return
        
        api_key = self.config.ai.api_key
        if not api_key:
            raise ValueError(
                "AI API key not configured. Set ICARUS_AI_API_KEY or GEMINI_API_KEY environment variable."
            )
        
        provider = self.config.ai.provider
        
        if provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(self.config.ai.model)
        else:
            raise ValueError(f"Unsupported AI provider: {provider}")
        
        self._initialized = True
        self.logger.info(f"AI engine initialized with provider: {provider}")
    
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
        
Answer the following question concisely and accurately:

{query}

Provide practical, actionable information. If the question relates to hacking or security testing, 
assume it's for authorized penetration testing purposes."""
        
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

Suggest 3-5 specific commands to achieve this goal. For each command:
1. Show the exact command
2. Explain what it does
3. Explain expected output

Format as a numbered list. Use common tools like nmap, netcat, curl, hydra, sqlmap, etc.
Keep explanations concise but thorough."""
        
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

Explain the following in detail: {topic}

Structure your response:
1. **Overview**: What is it?
2. **Impact**: What's the security impact?
3. **Affected Systems**: What systems/versions are vulnerable?
4. **Detection**: How can it be detected?
5. **Remediation**: How to fix or mitigate?

Be accurate and technical but accessible."""
        
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
        """Generate response from AI model."""
        try:
            if self.config.ai.provider == "gemini":
                response = await asyncio.to_thread(
                    self.model.generate_content,
                    prompt,
                    generation_config={
                        "max_output_tokens": self.config.ai.max_tokens,
                        "temperature": self.config.ai.temperature,
                    }
                )
                return response.text
            
        except Exception as e:
            self.logger.error(f"AI generation failed: {e}")
            return f"AI generation failed: {str(e)}\n\nPlease check your API key and try again."
