import json
import webbrowser

import branca.colormap as cm
import folium
import numpy as np
import pandas as pd
import pycountry_convert as pycc
from folium.plugins import MarkerCluster
from geopy.geocoders import Nominatim
from google.cloud import bigquery
from jinja2 import Template


def get_data_from_bigquery():
    # *****************************************
    # BigQuery query to pull PyPi download stats
    # *****************************************
    client = bigquery.Client()

    sql = r"""
    SELECT
    REGEXP_EXTRACT(details.python, r"[0-9]+\.[0-9]+") AS python_version,
    COUNT(*) AS num_downloads,
    FROM `bigquery-public-data.pypi.file_downloads`
    WHERE
    -- Only query the last 1 week of history
    DATE(timestamp)
        BETWEEN DATE_TRUNC(DATE_SUB(CURRENT_DATE(), INTERVAL 1 week), week)
        AND CURRENT_DATE()
    GROUP BY `python_version`
    ORDER BY `num_downloads` DESC
    """

    # Start the query, passing in the extra configuration.
    query_job = client.query(
        sql,
        # Location must match that of the dataset(s) referenced in the query
        # and of the destination table.
        location="US",
    )  # API request - starts the query

    result = query_job.result()
    df = result.to_dataframe()  # Waits for the query to finish

    df.to_json("doc/sampledata.json")

    return df


def get_data_from_file():
    # *****************************************
    # Read data from local json file
    # useful if free service quota is out
    # *****************************************
    return pd.read_json("doc/sampledata.json")


# TODO: change this to get_data_from_bigquery() when free service is available
df = get_data_from_file()

# credit goes to https://towardsdatascience.com/using-python-to-create-a-world-map-from-a-list-of-country-names-cd7480d03b10


def get_continent(col):
    try:
        cn_a2_code = pycc.country_name_to_country_alpha2(col)
    except Exception:
        cn_a2_code = "Unknown"
    try:
        cn_continent = pycc.country_alpha2_to_continent_code(cn_a2_code)
    except Exception:
        cn_continent = "Unknown"
    return (cn_a2_code, cn_continent)


def get_continent_4_a2(col):
    try:
        cn_continent = pycc.country_alpha2_to_continent_code(col)
    except Exception:
        cn_continent = "Unknown"
    return cn_continent


def get_country_name_4_a2(col):
    try:
        cn = pycc.country_alpha2_to_country_name(col)
    except Exception:
        cn = "Unknown"
    return cn


geolocator = Nominatim(user_agent="my_user_agent")


def geolocate(country):
    try:
        # Geolocate the center of the country
        loc = geolocator.geocode(country)
        # And return latitude and longitude
        return (loc.latitude, loc.longitude)
    except Exception:
        # Return missing value
        return np.nan


# *****************************************
# Get Geo data
# *****************************************
country = []
continent = []
lats = []
longs = []


for data in df["country_code"]:
    ctn = get_continent_4_a2(data)
    if ctn is not np.nan:
        continent.append(ctn)

    cn = get_country_name_4_a2(data)
    if cn is not np.nan:
        country.append(cn)
        cds = geolocate(cn)
        if cds is not np.nan:
            lats.append(cds[0])
            longs.append(cds[1])
        else:
            lats.append(0)
            longs.append(0)

df["Country"] = country
df["Continent"] = continent
df["Latitude"] = lats
df["Longitude"] = longs


# *****************************************
# Create visual
# *****************************************


class MarkerWithProps(folium.Marker):
    _template = Template(
        """
        {% macro script(this, kwargs) %}
        var {{this.get_name()}} = L.marker(
            [{{this.location[0]}}, {{this.location[1]}}],
            {
                icon: new L.Icon.Default(),
                {%- if this.draggable %}
                draggable: true,
                autoPan: true,
                {%- endif %}
                {%- if this.props %}
                props : {{ this.props }}
                {%- endif %}
                }
            )
            .addTo({{this._parent.get_name()}});
        {% endmacro %}
        """
    )

    def __init__(
        self,
        location,
        popup=None,
        tooltip=None,
        icon=None,
        name=None,
        draggable=False,
        props=None,
        radius=None,
    ):
        super().__init__(
            location=location,
            popup=popup,
            radius=radius,
            tooltip=tooltip,
            icon=icon,
            draggable=draggable,
        )
        self.props = json.loads(json.dumps(props))


icon_create_function = """
    function(cluster) {
        var cc = cluster.getChildCount();
        var markers = cluster.getAllChildMarkers();

        var sum = 0;
        for(var i in markers) {
            sum += markers[i].options.props.downloads;
        }
        var avg = sum/cluster.getChildCount();

        function verifica_Media(media) {
            if (media < 520) {
                return 'marker-cluster marker-cluster-large'
            }
            else if (media >=  520 && media <= 600) {
                return 'marker-cluster marker-cluster-medium'
            }
            else  if (media > 600) {
                return 'marker-cluster marker-cluster-small'
            }
        }

        return L.divIcon({
             html: '<div style="display:flex;justify-content:center;align-items:center;font-size:7pt;">'+ sum +'</div>',
             className: verifica_Media(avg),
             iconSize: new L.Point(40, 40)

        });
    }
"""

# create a world map
world_map = folium.Map(location=[10, 10], width="%100", height="%100", zoom_start=3)

# create a cluster with icon creation override
marker_cluster_sum = MarkerCluster(icon_create_function=icon_create_function)

# create a regular cluster
marker_cluster_circle = MarkerCluster()

# create a color map
min = np.min(df["num_downloads"])
max = np.max(df["num_downloads"])
colormap = cm.StepColormap(
    colors=["green", "yellow", "orange", "red"],
    index=[min, 10, 100, 500, max],
    vmin=min,
    vmax=max,
)

# for each coordinate, create circlemarker of user percent
for i in range(len(df)):
    lat = df.iloc[i]["Latitude"]
    long = df.iloc[i]["Longitude"]
    num = df.iloc[i]["num_downloads"]

    popup_text = """{} downloads in {} <br>"""
    popup_text = popup_text.format(df.iloc[i]["num_downloads"], df.iloc[i]["Country"])

    radius = num / 100
    marker = MarkerWithProps(
        location=[df.iloc[i]["Latitude"], df.iloc[i]["Longitude"]],
        props={"downloads": int(df.iloc[i]["num_downloads"])},
        tooltip=popup_text,
        radius=radius,
    )
    marker.add_to(marker_cluster_sum)

    marker2 = folium.CircleMarker(
        location=[lat, long],
        radius=radius,
        tooltip=popup_text,
        color=colormap(num),
        fill_opacity=0.5,
        fill_color=colormap(num),
    )
    marker2.add_to(marker_cluster_circle)

marker_cluster_circle.add_to(world_map)
marker_cluster_sum.add_to(world_map)

world_map.save("map.html")
webbrowser.open("map.html")


# try heatmap

m = folium.Map(location=[10, 10], width="%100", height="%100", zoom_start=2)

for i in range(len(df)):
    lat = df.iloc[i]["Latitude"]
    long = df.iloc[i]["Longitude"]
    num = df.iloc[i]["num_downloads"]
    folium.Circle(
        location=[lat, long], radius=200, fill=True, color=colormap(num)
    ).add_to(m)
m.save("map2.html")
webbrowser.open("map2.html")
