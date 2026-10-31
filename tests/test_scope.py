import pytest
from patchlens.scope import Scope

def test_valid_initialization():
    scope = Scope("https://example.com/dashboard")
    assert scope.host == "example.com"
            
    assert scope.scheme == "https"
        

def test_invalid_scheme():
    with pytest.raises(ValueError):
        Scope("ftp://example.com")

    with pytest.raises(ValueError):
        Scope("ftp:///etc/passwd")


def test_missing_host():
    with pytest.raises(ValueError):
            Scope("https://")

def test_same_domain():
    scope = Scope("https://example.com/dashboard")
    
    assert scope.in_scope("https://example.com/about")
    assert scope.in_scope("https://example.com/contact")
        

def test_relative_path():
    scope = Scope("https://example.com/dashboard")

    assert scope.in_scope("/login") is True
    assert scope.in_scope("dashboard") is True


def test_external_domain():
    scope = Scope("https://example.com/dashboard")
    assert scope.in_scope("https://google.com") is False
            
    assert scope.in_scope("https://sub.example.com") is False


def test_non_http_protocol():
    scope = Scope("https://example.com/dashboard")
    
    assert scope.in_scope("mailto:admin@example.com") is False
            
    assert scope.in_scope("javascript:void(0)") is False
            
    assert scope.in_scope("tel:+123456789") is False
        
            

    assert scope.in_scope("") is False
    
    


