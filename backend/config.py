from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    '''
    Application settings and configuration.
    Loads from environment variables or .env file automatically.
    '''
    project_name: str = "AI-SOC"
    api_v1_str: str = "/api/v1"

    # Database
    sqlite_db_path: str = "sqlite:///./soc_data.db"

    # Correlation
    correlation_window_seconds: int = 300  # 5 minutes default

    # AI settings (to be used later)
    ollama_host: str = "http://localhost:11434"
    ai_model_name: str = "qwen2.5:7b"
    # Detection Thresholds
    brute_force_threshold_count: int = 5
    port_scan_unique_ports: int = 5

    model_config = {"env_file": ".env"}

settings = Settings()
