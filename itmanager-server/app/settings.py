from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "ITManager"
    base_url: str = "https://panel.karakoc.local"

    mssql_host: str = "192.168.1.32"
    mssql_db: str = "itmanager"
    mssql_user: str = "sa"
    mssql_password: str = "1453"
    mssql_driver: str = "ODBC Driver 18 for SQL Server"
    mssql_trust_cert: bool = True

    agent_enrollment_token: str = "KARAKOC_ENROLL_CHANGE_ME"
    agent_poll_seconds: int = 10

    # Agent release packages are stored on the server filesystem.
    # Example structure:
    #   <agent_releases_dir>/windows/itmanager-agent-windows-0.2.0.zip
    agent_releases_dir: str = "agent-releases"

    # Panel considers a device online if it has talked to the server within this window.
    panel_online_cutoff_seconds: int = 300

    sso_header_name: str = "X-Remote-User"

    class Config:
        env_file = ".env"


settings = Settings()
