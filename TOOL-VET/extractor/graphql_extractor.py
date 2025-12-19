"""GraphQL 엔드포인트 감지 및 스키마 추출"""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def detect_graphql_endpoint(base_url: str) -> Optional[str]:
    """기본 URL에서 GraphQL 엔드포인트 추정"""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    # 일반적인 GraphQL 엔드포인트 경로
    common_paths = [
        "/graphql",
        "/graph",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/query",
        "/gql",
    ]
    
    for path in common_paths:
        endpoint = f"{base}{path}"
        if _is_graphql_endpoint(endpoint):
            return endpoint
    
    return None


def _is_graphql_endpoint(url: str) -> bool:
    """URL이 GraphQL 엔드포인트인지 확인"""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # 간단한 GraphQL 쿼리로 테스트
        test_query = {"query": "{ __typename }"}
        response = requests.post(
            url,
            json=test_query,
            headers={"Content-Type": "application/json"},
            timeout=5,
            verify=False,
        )
        
        if response.status_code == 200:
            try:
                data = response.json()
                # GraphQL 응답은 보통 {"data": {...}} 형식
                return "data" in data or "errors" in data
            except json.JSONDecodeError:
                return False
    except Exception:
        pass
    
    return False


def introspect_graphql_schema(endpoint: str, headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    """GraphQL Introspection 쿼리로 스키마 정보 추출"""
    introspection_query = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                ...FullType
            }
            directives {
                name
                description
                locations
                args {
                    ...InputValue
                }
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type { ...TypeRef }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    """
    
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        payload = {"query": introspection_query}
        request_headers = {"Content-Type": "application/json"}
        if headers:
            request_headers.update(headers)
        
        response = requests.post(
            endpoint,
            json=payload,
            headers=request_headers,
            timeout=10,
            verify=False,
        )
        
        if response.status_code == 200:
            data = response.json()
            if "data" in data and data.get("data"):
                return data["data"]
            # Introspection이 비활성화된 경우
            if "errors" in data:
                return {"introspection_disabled": True, "errors": data["errors"]}
    except Exception:
        pass
    
    return None


def extract_operations_from_schema(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    """GraphQL 스키마에서 쿼리/뮤테이션 목록 추출"""
    operations: List[Dict[str, Any]] = []
    
    if not schema or "__schema" not in schema:
        return operations
    
    schema_data = schema.get("__schema", {})
    
    # Query Type
    query_type_name = schema_data.get("queryType", {}).get("name")
    if query_type_name:
        # types 배열에서 queryType 찾기
        types = schema_data.get("types", [])
        query_type = next((t for t in types if t.get("name") == query_type_name), None)
        if query_type and query_type.get("fields"):
            for field in query_type["fields"]:
                operations.append({
                    "type": "query",
                    "name": field.get("name", ""),
                    "description": field.get("description"),
                    "args": field.get("args", []),
                })
    
    # Mutation Type
    mutation_type_name = schema_data.get("mutationType", {}).get("name")
    if mutation_type_name:
        types = schema_data.get("types", [])
        mutation_type = next((t for t in types if t.get("name") == mutation_type_name), None)
        if mutation_type and mutation_type.get("fields"):
            for field in mutation_type["fields"]:
                operations.append({
                    "type": "mutation",
                    "name": field.get("name", ""),
                    "description": field.get("description"),
                    "args": field.get("args", []),
                })
    
    # Subscription Type
    subscription_type_name = schema_data.get("subscriptionType", {}).get("name")
    if subscription_type_name:
        types = schema_data.get("types", [])
        subscription_type = next((t for t in types if t.get("name") == subscription_type_name), None)
        if subscription_type and subscription_type.get("fields"):
            for field in subscription_type["fields"]:
                operations.append({
                    "type": "subscription",
                    "name": field.get("name", ""),
                    "description": field.get("description"),
                    "args": field.get("args", []),
                })
    
    return operations


def check_introspection_enabled(endpoint: str, headers: Optional[Dict[str, str]] = None) -> bool:
    """GraphQL Introspection이 활성화되어 있는지 확인"""
    introspection_query = {"query": "query{__schema{queryType{name}}}"}
    
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        request_headers = {"Content-Type": "application/json"}
        if headers:
            request_headers.update(headers)
        
        response = requests.post(
            endpoint,
            json=introspection_query,
            headers=request_headers,
            timeout=5,
            verify=False,
        )
        
        if response.status_code == 200:
            data = response.json()
            # Introspection이 활성화된 경우 data에 __schema 정보가 있음
            if "data" in data and data.get("data", {}).get("__schema"):
                return True
            # Introspection이 비활성화된 경우 에러 반환
            if "errors" in data:
                error_messages = [e.get("message", "") for e in data.get("errors", [])]
                if any("introspection" in msg.lower() for msg in error_messages):
                    return False
    except Exception:
        pass
    
    return False

