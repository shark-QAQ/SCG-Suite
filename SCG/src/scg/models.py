"""
SCG 插件的响应模型
用于表示扫描结果中的问题或错误。
"""
from pydantic import BaseModel, Field
from typing import List, Literal

# 定义 SCG 插件的响应模型
class ScgIssue(BaseModel):
    rule_id: str = Field(description="规则ID，如 SCG-001")
    severity: Literal["high", "medium", "low"] = Field(description="严重级别")
    message: str = Field(description="错误描述")
    suggestion: str = Field(description="修复建议")

# 定义 SCG 插件的扫描结果模型
class ScgScanResult(BaseModel):
    safe: bool = Field(description="是否安全")
    summary: str = Field(description="一句话总结")
    issues: List[ScgIssue] = Field(default_factory=list, description="发现的问题列表")