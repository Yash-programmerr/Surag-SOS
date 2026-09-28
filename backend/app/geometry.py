import json
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree
from fastapi import HTTPException
from shapely.geometry import mapping, shape
from shapely.validation import explain_validity


MAX_BYTES = 5 * 1024 * 1024
MAX_VERTICES = 5000


def normalize_geometry(value: dict) -> dict:
    if value.get("type") == "Feature":
        value = value.get("geometry") or {}
    elif value.get("type") == "FeatureCollection":
        features = value.get("features", [])
        if len(features) != 1:
            raise HTTPException(422, "Import one polygon feature at a time")
        value = features[0].get("geometry") or {}
    if value.get("type") not in {"Polygon", "MultiPolygon"}:
        raise HTTPException(422, "AOI must be a Polygon or MultiPolygon")
    try:
        geom = shape(value)
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, "Invalid polygon coordinates") from exc
    if geom.is_empty or not geom.is_valid:
        raise HTTPException(422, f"Invalid polygon: {explain_validity(geom)}")
    vertices = sum(len(ring.coords) for poly in ([geom] if geom.geom_type == "Polygon" else geom.geoms)
                   for ring in [poly.exterior, *poly.interiors])
    if vertices > MAX_VERTICES:
        raise HTTPException(422, "AOI exceeds 5,000 vertices")
    min_x, min_y, max_x, max_y = geom.bounds
    if not (-180 <= min_x <= max_x <= 180 and -90 <= min_y <= max_y <= 90):
        raise HTTPException(422, "AOI coordinates must be WGS84 longitude/latitude")
    if max_x - min_x > 180:
        raise HTTPException(422, "AOIs crossing the antimeridian must be split")
    if geom.area > 1:
        raise HTTPException(422, "AOI is too large; split it into smaller areas")
    return mapping(geom)


def parse_import(filename: str, content: bytes) -> dict:
    if len(content) > MAX_BYTES:
        raise HTTPException(413, "AOI file exceeds 5 MB")
    try:
        if filename.lower().endswith((".geojson", ".json")):
            return normalize_geometry(json.loads(content))
        if filename.lower().endswith(".kml"):
            root = ElementTree.fromstring(content)
            polygons = root.findall(".//{*}Polygon")
            if len(polygons) != 1:
                raise HTTPException(422, "KML must contain exactly one Polygon")
            rings = []
            for parent in ("outerBoundaryIs", "innerBoundaryIs"):
                for boundary in polygons[0].findall(f"{{*}}{parent}"):
                    coordinates = boundary.find(".//{*}coordinates")
                    if coordinates is None or not coordinates.text:
                        raise HTTPException(422, "KML polygon has no coordinates")
                    rings.append([[float(part) for part in point.split(",")[:2]] for point in coordinates.text.split()])
            return normalize_geometry({"type": "Polygon", "coordinates": rings})
    except (json.JSONDecodeError, ParseError, ValueError) as exc:
        raise HTTPException(422, "Invalid AOI file") from exc
    raise HTTPException(415, "Use a GeoJSON or KML file")
