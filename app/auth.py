"""API key authentication middleware."""

from fastapi import Header, HTTPException, status

from app.config import config


async def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")) -> str:
    """
    Verify the API key from the request header.
    
    Args:
        x_api_key: API key from x-api-key header
        
    Returns:
        The validated API key
        
    Raises:
        HTTPException: If API key is missing or invalid
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key"
        )
    
    if x_api_key != config.X_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    return x_api_key
