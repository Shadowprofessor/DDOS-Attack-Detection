# -*- coding: utf-8 -*-
"""
Real-time WebSocket dashboard module.
"""
from src.web.realtime_dashboard.broadcaster import DashboardBroadcaster, get_broadcaster
from src.web.realtime_dashboard.router import router as dashboard_router

__all__ = [
    "DashboardBroadcaster",
    "get_broadcaster",
    "dashboard_router",
]
