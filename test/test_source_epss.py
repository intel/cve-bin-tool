from pathlib import Path

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.data_sources import epss_source


class TestSourceEPSS:
    @classmethod
    def setup_class(cls):
        cls.epss = epss_source.Epss_Source()
        cls.epss.file_name = (
            Path(__file__).parent.resolve() / "epss" / "epss_score_test.csv"
        )

    final_data = [
        ("CVE-1999-0001", 1, "0.011", "0.82987"),
        ("CVE-2019-10354", 1, "0.00287", "0.64385"),
        ("CVE-1999-0003", 1, "0.999", "0.88555"),
        ("CVE-2023-28143", 1, "0.00042", "0.05685"),
        ("CVE-2017-15360", 1, "0.00078", "0.31839"),
        ("CVE-2008-4444", 1, "0.07687", "0.93225"),
        ("CVE-1999-0007", 1, "0.00180", "0.54020"),
    ]

    def test_parse_epss(self):
        # EPSS need metrics table to populated in the database. To get the EPSS metric id from table.
        cvedb = CVEDB()
        # creating table
        cvedb.init_database()
        # populating metrics
        cvedb.populate_metrics()
        cursor = cvedb.db_open_and_get_cursor()
        # seting EPSS_metric_id
        self.epss.EPSS_id_finder(cursor)
        # parsing the data
        self.epss_data = self.epss.parse_epss_data(self.epss.file_name)
        cvedb.db_close()
        assert self.epss_data == self.final_data
