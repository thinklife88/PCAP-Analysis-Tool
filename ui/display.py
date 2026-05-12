"""Rich display helpers."""

from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, TextColumn
from rich.table import Table

console = Console()


def print_header(title: str):
    console.print(Panel(f"[bold cyan]{title}[/bold cyan]", expand=False))


def print_success(message: str):
    console.print(f"[green][SUCCESS][/green] {message}")


def print_error(message: str):
    console.print(f"[red][ERROR][/red] {message}")


def print_warning(message: str):
    console.print(f"[yellow][WARN][/yellow] {message}")


def print_info(message: str):
    console.print(f"[blue][INFO][/blue] {message}")


def print_table(title: str, columns: List[str], rows: List[List[Any]]):
    table = Table(title=title, show_header=True, header_style="bold magenta")
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*[str(item) for item in row])
    console.print(table)


def print_stats(stats: Dict[str, Any], title: str = "统计信息"):
    table = Table(title=title, show_header=False)
    table.add_column("指标", style="cyan")
    table.add_column("值", style="green")
    for key, value in stats.items():
        table.add_row(str(key), str(value))
    console.print(table)


def create_progress():
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        TextColumn(" "),
        TextColumn("{task.completed} packets"),
        console=console,
    )
