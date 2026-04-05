"""
Phase 0: Skill Artifact Extraction

Extracts and preprocesses skill artifacts for security analysis.
"""

import os
import re
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

from skill_audit.schemas import SkillArtifact
from skill_audit.patterns import MaliciousPatterns

logger = logging.getLogger(__name__)

# Directories to exclude from scanning
EXCLUDED_DIRS = {"skill-audit", "__pycache__", "node_modules", ".git", ".venv", "venv"}

# Sensitive files to explicitly scan (even though they don't match code extensions)
SENSITIVE_FILES = [".env", ".env.local", ".env.production", ".env.staging"]


class SkillArtifactExtractor:
    """Extracts structured data from skill files"""

    SUPPORTED_CODE_EXTENSIONS = [".py", ".js", ".ts", ".go", ".rs", ".cpp", ".c"]
    PROMPT_EXTENSIONS = [".md", ".txt", ".prompt"]
    MANIFEST_FILES = ["manifest.json", "manifest.yaml", "skill.yaml", "skill.json"]

    def __init__(self):
        self.pattern_scanner = MaliciousPatterns()

    def extract_from_path(self, skill_path: str) -> SkillArtifact:
        """
        Extract skill artifact from filesystem path.

        Args:
            skill_path: Path to skill directory or Python file

        Returns:
            SkillArtifact with extracted data
        """
        skill_path = Path(skill_path).resolve()

        if not skill_path.exists():
            raise FileNotFoundError(f"Skill path not found: {skill_path}")

        # Determine if directory or single file
        if skill_path.is_dir():
            return self._extract_from_directory(skill_path)
        else:
            return self._extract_from_file(skill_path)

    def _is_excluded_path(self, path: Path) -> bool:
        """Check if a path should be excluded from scanning"""
        parts = path.parts
        for part in parts:
            if part in EXCLUDED_DIRS:
                return True
        return False

    def _extract_from_directory(self, skill_dir: Path) -> SkillArtifact:
        """Extract from skill directory"""
        logger.info(f"Extracting skill artifact from directory: {skill_dir}")

        # Find manifest
        manifest = self._find_and_parse_manifest(skill_dir)

        # Extract code files
        code_files = self._extract_code_files(skill_dir)

        # Extract prompt files
        prompts = self._extract_prompts(skill_dir)

        # Extract description from manifest or README
        description = self._extract_description(skill_dir, manifest)

        # Extract permissions
        declared_permissions = self._extract_permissions(manifest, code_files)

        # Extract external references from all content
        all_content = "\n".join(code_files.values()) + "\n".join(prompts) + description
        external_references = self.pattern_scanner.extract_external_references(
            all_content
        )

        # Extract dependencies
        dependencies = self._extract_dependencies(skill_dir, code_files)

        return SkillArtifact(
            skill_name=manifest.get("name", skill_dir.name),
            skill_path=str(skill_dir),
            manifest=manifest,
            description=description,
            prompts=prompts,
            declared_permissions=declared_permissions,
            code_files=code_files,
            external_references=external_references,
            dependencies=dependencies,
        )

    def _extract_from_file(self, skill_file: Path) -> SkillArtifact:
        """Extract from single skill file (code or .md prompt file)"""
        logger.info(f"Extracting skill artifact from file: {skill_file}")

        # Read file content
        try:
            with open(skill_file, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Failed to read skill file: {e}")
            content = ""

        # Check if this is a .md prompt file
        is_prompt_file = skill_file.suffix.lower() in self.PROMPT_EXTENSIONS

        if is_prompt_file:
            # Treat .md file as a PromptSkill
            logger.info(f"Detected prompt file (.md): {skill_file.name}")
            code_files = {}  # No code files for pure prompt skills
            prompts = [content]  # The entire .md content is the prompt

            # Extract metadata from markdown headers/front matter
            manifest = self._extract_metadata_from_markdown(content, skill_file.stem)
            description = self._extract_description_from_markdown(content)
        else:
            # Regular code file
            code_files = {skill_file.name: content}
            manifest = self._extract_metadata_from_code(content, skill_file.stem)
            description = self._extract_description_from_code(content)
            prompts = self._extract_prompts_from_code(content)

        # Extract permissions
        declared_permissions = self._extract_permissions(manifest, code_files)

        # Extract external references
        external_references = self.pattern_scanner.extract_external_references(content)

        # Extract dependencies
        dependencies = self._extract_dependencies_from_code(content)

        return SkillArtifact(
            skill_name=manifest.get("name", skill_file.stem),
            skill_path=str(skill_file),
            manifest=manifest,
            description=description,
            prompts=prompts,
            declared_permissions=declared_permissions,
            code_files=code_files,
            external_references=external_references,
            dependencies=dependencies,
        )

    def _find_and_parse_manifest(self, skill_dir: Path) -> Dict[str, Any]:
        """Find and parse manifest file"""
        for manifest_name in self.MANIFEST_FILES:
            manifest_path = skill_dir / manifest_name
            if manifest_path.exists():
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        if manifest_name.endswith(".json"):
                            return json.load(f)
                        else:
                            return yaml.safe_load(f) or {}
                except Exception as e:
                    logger.warning(f"Failed to parse manifest {manifest_path}: {e}")

        return {}

    def _extract_code_files(self, skill_dir: Path) -> Dict[str, str]:
        """Extract all code files from directory"""
        code_files = {}

        for ext in self.SUPPORTED_CODE_EXTENSIONS:
            for code_file in skill_dir.rglob(f"*{ext}"):
                # Skip excluded directories
                try:
                    relative_path = code_file.relative_to(skill_dir)
                except ValueError:
                    continue

                if self._is_excluded_path(relative_path):
                    continue

                try:
                    with open(code_file, "r", encoding="utf-8") as f:
                        content = f.read()
                        code_files[str(relative_path)] = content
                except Exception as e:
                    logger.warning(f"Failed to read code file {code_file}: {e}")

        # Also scan sensitive files (.env etc.)
        for sensitive_name in SENSITIVE_FILES:
            for env_file in skill_dir.rglob(sensitive_name):
                try:
                    relative_path = env_file.relative_to(skill_dir)
                except ValueError:
                    continue

                if self._is_excluded_path(relative_path):
                    continue

                try:
                    with open(env_file, "r", encoding="utf-8") as f:
                        content = f.read()
                        code_files[str(relative_path)] = content
                        logger.info(f"Scanned sensitive file: {relative_path}")
                except Exception as e:
                    logger.warning(f"Failed to read sensitive file {env_file}: {e}")

        return code_files

    def _extract_prompts(self, skill_dir: Path) -> List[str]:
        """Extract prompt templates"""
        prompts = []
        processed_files = set()

        # Priority 1: Extract skill.md (main skill definition file for Claude Code skills)
        skill_md_files = ["skill.md", "SKILL.md", "Skill.md"]
        for skill_md_name in skill_md_files:
            skill_md_path = skill_dir / skill_md_name
            if skill_md_path.exists() and skill_md_path not in processed_files:
                try:
                    with open(skill_md_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        prompts.append(content)
                        processed_files.add(skill_md_path)
                        logger.info(f"Extracted skill definition file: {skill_md_name}")
                except Exception as e:
                    logger.warning(f"Failed to read skill file {skill_md_path}: {e}")

        # Priority 2: Look for files with "prompt" in the name
        for ext in self.PROMPT_EXTENSIONS:
            for prompt_file in skill_dir.rglob(f"*{ext}"):
                if prompt_file in processed_files:
                    continue

                # Skip excluded directories
                try:
                    relative_path = prompt_file.relative_to(skill_dir)
                except ValueError:
                    continue

                if self._is_excluded_path(relative_path):
                    continue

                if "prompt" in prompt_file.name.lower():
                    try:
                        with open(prompt_file, "r", encoding="utf-8") as f:
                            prompts.append(f.read())
                            processed_files.add(prompt_file)
                    except Exception as e:
                        logger.warning(f"Failed to read prompt file {prompt_file}: {e}")

        return prompts

    def _extract_description(
        self, skill_dir: Path, manifest: Dict[str, Any]
    ) -> str:
        """Extract skill description"""
        # Try manifest first
        if "description" in manifest:
            return manifest["description"]

        # Try README
        for readme_name in ["README.md", "README.txt", "README"]:
            readme_path = skill_dir / readme_name
            if readme_path.exists():
                try:
                    with open(readme_path, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception:
                    pass

        return ""

    def _extract_description_from_code(self, code: str) -> str:
        """Extract description from code docstring"""
        # Match module-level docstring
        match = re.search(r'^\s*"""(.+?)"""', code, re.DOTALL | re.MULTILINE)
        if match:
            return match.group(1).strip()

        match = re.search(r"^\s*'''(.+?)'''", code, re.DOTALL | re.MULTILINE)
        if match:
            return match.group(1).strip()

        return ""

    def _extract_prompts_from_code(self, code: str) -> List[str]:
        """Extract embedded prompts from code"""
        prompts = []

        # Look for prompt_file assignments
        for match in re.finditer(
            r'prompt_file\s*=\s*["\']([^"\']+)["\']', code
        ):
            prompts.append(f"Prompt file reference: {match.group(1)}")

        # Look for prompt templates in strings
        for match in re.finditer(
            r'(?:prompt|template)\s*=\s*["\']([^"\']{50,})["\']', code, re.DOTALL
        ):
            prompts.append(match.group(1))

        return prompts

    def _extract_permissions(
        self, manifest: Dict[str, Any], code_files: Dict[str, str]
    ) -> List[str]:
        """Extract declared permissions"""
        permissions = set()

        # From manifest
        if "permissions" in manifest:
            perms = manifest["permissions"]
            if isinstance(perms, list):
                permissions.update(perms)
            elif isinstance(perms, dict):
                permissions.update(perms.keys())

        # From code (look for requires_permissions, declared_permissions, etc.)
        for code in code_files.values():
            for match in re.finditer(
                r'(?:requires_permissions|declared_permissions)\s*=\s*\[([^\]]+)\]',
                code,
            ):
                perm_list = match.group(1)
                for perm in re.findall(r'["\']([^"\']+)["\']', perm_list):
                    permissions.add(perm)

        return list(permissions)

    def _extract_dependencies(
        self, skill_dir: Path, code_files: Dict[str, str]
    ) -> List[str]:
        """Extract external dependencies"""
        dependencies = set()

        # From requirements.txt
        req_file = skill_dir / "requirements.txt"
        if req_file.exists():
            try:
                with open(req_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Extract package name (before ==, >=, etc.)
                            pkg = re.split(r"[=<>!]", line)[0].strip()
                            dependencies.add(pkg)
            except Exception as e:
                logger.warning(f"Failed to read requirements.txt: {e}")

        # From package.json
        pkg_json = skill_dir / "package.json"
        if pkg_json.exists():
            try:
                with open(pkg_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for dep_type in ["dependencies", "devDependencies"]:
                        if dep_type in data:
                            dependencies.update(data[dep_type].keys())
            except Exception as e:
                logger.warning(f"Failed to read package.json: {e}")

        # From imports in code
        for code in code_files.values():
            deps = self._extract_dependencies_from_code(code)
            dependencies.update(deps)

        return list(dependencies)

    def _extract_dependencies_from_code(self, code: str) -> List[str]:
        """Extract dependencies from import statements"""
        dependencies = set()

        # Python imports
        for match in re.finditer(r"^\s*(?:from|import)\s+([a-zA-Z0-9_]+)", code, re.MULTILINE):
            module = match.group(1)
            # Exclude standard library (basic check)
            if module not in [
                "os",
                "sys",
                "re",
                "json",
                "time",
                "datetime",
                "pathlib",
                "typing",
                "logging",
                "unittest",
            ]:
                dependencies.add(module)

        # JavaScript/TypeScript imports
        for match in re.finditer(
            r'(?:import|require)\s*\(["\']([^"\']+)["\']\)', code
        ):
            module = match.group(1)
            if not module.startswith("."):  # External module
                dependencies.add(module.split("/")[0])

        return list(dependencies)

    def _extract_metadata_from_code(self, code: str, default_name: str) -> Dict[str, Any]:
        """Extract metadata from code comments/docstrings"""
        metadata = {"name": default_name}

        # Look for name
        match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', code)
        if match:
            metadata["name"] = match.group(1)

        # Look for author
        match = re.search(r'author\s*=\s*["\']([^"\']+)["\']', code)
        if match:
            metadata["author"] = match.group(1)

        # Look for version
        match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', code)
        if match:
            metadata["version"] = match.group(1)

        return metadata

    def _extract_metadata_from_markdown(self, markdown: str, default_name: str) -> Dict[str, Any]:
        """Extract metadata from markdown YAML front matter or headers"""
        metadata = {"name": default_name}

        # Try to extract YAML front matter (between --- delimiters)
        front_matter_match = re.match(r'^---\s*\n(.*?)\n---\s*\n', markdown, re.DOTALL)
        if front_matter_match:
            try:
                front_matter = yaml.safe_load(front_matter_match.group(1))
                if isinstance(front_matter, dict):
                    if "name" in front_matter:
                        metadata["name"] = front_matter["name"]
                    if "author" in front_matter:
                        metadata["author"] = front_matter["author"]
                    if "version" in front_matter:
                        metadata["version"] = front_matter["version"]
                    return metadata
            except Exception as e:
                logger.warning(f"Failed to parse YAML front matter: {e}")

        # Fallback: Extract from markdown headers (# Title)
        title_match = re.search(r'^#\s+(.+)$', markdown, re.MULTILINE)
        if title_match:
            metadata["name"] = title_match.group(1).strip()

        return metadata

    def _extract_description_from_markdown(self, markdown: str) -> str:
        """Extract description from markdown content"""
        # Remove YAML front matter if present
        content = re.sub(r'^---\s*\n.*?\n---\s*\n', '', markdown, flags=re.DOTALL)

        # Try to extract first paragraph after the title
        # Pattern: Skip title, get first non-empty paragraph
        lines = content.split('\n')
        description_lines = []
        skip_title = False

        for line in lines:
            stripped = line.strip()
            # Skip title line
            if stripped.startswith('#'):
                skip_title = True
                continue

            # Start collecting after title
            if skip_title and stripped:
                description_lines.append(stripped)
                # Stop after first paragraph (empty line break)
                if not stripped:
                    break
            elif len(description_lines) > 0 and not stripped:
                break

        if description_lines:
            return ' '.join(description_lines[:5])  # First 5 lines max

        # Fallback: return first 500 chars
        return content[:500].strip()


def create_skill_artifact_extractor() -> SkillArtifactExtractor:
    """Factory function to create extractor"""
    return SkillArtifactExtractor()
