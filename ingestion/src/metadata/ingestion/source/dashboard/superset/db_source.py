#  Copyright 2021 Collate
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""
Superset source module
"""

import traceback
from typing import Iterable, List, Optional

from sqlalchemy.engine import Engine

from metadata.generated.schema.api.data.createChart import CreateChartRequest
from metadata.generated.schema.api.data.createDashboard import CreateDashboardRequest
from metadata.generated.schema.entity.data.chart import Chart, ChartType
from metadata.generated.schema.entity.data.table import Table
from metadata.generated.schema.entity.services.connections.metadata.openMetadataConnection import (
    OpenMetadataConnection,
)
from metadata.generated.schema.metadataIngestion.workflow import (
    Source as WorkflowSource,
)
from metadata.ingestion.source.dashboard.superset.mixin import SupersetSourceMixin
from metadata.ingestion.source.dashboard.superset.queries import (
    FETCH_ALL_CHARTS,
    FETCH_DASHBOARDS,
)
from metadata.utils import fqn
from metadata.utils.helpers import get_standard_chart_type
from metadata.utils.logger import ingestion_logger

logger = ingestion_logger()


class SupersetDBSource(SupersetSourceMixin):
    """
    Superset DB Source Class
    """

    def __init__(self, config: WorkflowSource, metadata_config: OpenMetadataConnection):
        super().__init__(config, metadata_config)
        self.engine: Engine = self.client

    def prepare(self):
        """
        Fetching all charts available in superset
        this step is done because fetch_total_charts api fetches all
        the required information which is not available in fetch_charts_with_id api
        """
        charts = self.engine.execute(FETCH_ALL_CHARTS)
        for chart in charts:
            self.all_charts[chart["id"]] = dict(chart)

    def get_dashboards_list(self) -> Optional[List[object]]:
        """
        Get List of all dashboards
        """
        dashboards = self.engine.execute(FETCH_DASHBOARDS)
        for dashboard in dashboards:
            yield dict(dashboard)

    def yield_dashboard(
        self, dashboard_details: dict
    ) -> Iterable[CreateDashboardRequest]:
        """
        Method to Get Dashboard Entity
        """
        dashboard_request = CreateDashboardRequest(
            name=dashboard_details["id"],
            displayName=dashboard_details["dashboard_title"],
            description="",
            dashboardUrl=f"/superset/dashboard/{dashboard_details['id']}/",
            charts=[
                fqn.build(
                    self.metadata,
                    entity_type=Chart,
                    service_name=self.context.dashboard_service.fullyQualifiedName.__root__,
                    chart_name=chart.name.__root__,
                )
                for chart in self.context.charts
            ],
            service=self.context.dashboard_service.fullyQualifiedName.__root__,
        )
        yield dashboard_request
        self.register_record(dashboard_request=dashboard_request)

    def _get_datasource_fqn_for_lineage(self, chart_json, db_service_name):
        return (
            self._get_datasource_fqn(chart_json, db_service_name)
            if chart_json.get("table_name")
            else None
        )

    def yield_dashboard_chart(
        self, dashboard_details: dict
    ) -> Optional[Iterable[CreateChartRequest]]:
        """
        Metod to fetch charts linked to dashboard
        """
        for chart_id in self._get_charts_of_dashboard(dashboard_details):
            chart_json = self.all_charts.get(chart_id)
            if not chart_json:
                logger.warning(f"chart details for id: {chart_id} not found, skipped")
                continue
            chart = CreateChartRequest(
                name=chart_json["id"],
                displayName=chart_json.get("slice_name"),
                description=chart_json.get("description"),
                chartType=get_standard_chart_type(
                    chart_json.get("viz_type", ChartType.Other.value)
                ),
                chartUrl=f"/explore/?slice_id={chart_json['id']}",
                service=self.context.dashboard_service.fullyQualifiedName.__root__,
            )
            yield chart

    def _get_database_name(self, sqa_str: str) -> str:
        if sqa_str:
            return sqa_str.split("/")[-1]
        return None

    def _get_datasource_fqn(
        self, chart_json: dict, db_service_name: str
    ) -> Optional[str]:
        if db_service_name:
            try:
                dataset_fqn = fqn.build(
                    self.metadata,
                    entity_type=Table,
                    table_name=chart_json.get("table_name"),
                    database_name=self._get_database_name(
                        chart_json.get("sqlalchemy_uri")
                    ),
                    schema_name=chart_json.get("schema"),
                    service_name=db_service_name,
                )
                return dataset_fqn
            except Exception as err:
                logger.debug(traceback.format_exc())
                logger.warning(
                    f"Failed to fetch Datasource with id [{chart_json.get('table_name')}]: {err}"
                )
        return None
