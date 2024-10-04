import sys

# sys.path.append('C:\\Users\\russh\\git\\lib4sbom\\build\\lib')
sys.path.append("C:\\Users\\russh\\git\\lib4sbom")
import hashlib
from uuid import uuid4

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.file import SBOMFile
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM, SBOMData


def generate_clinician_sbom():
    sbom = SBOM()
    sbom.set_type(sbom_type="cyclonedx")
    sbom.set_version("1.4")
    sbom.set_uuid(str(uuid4()))
    sbom.set_bom_version("2")

    sbom_doc = SBOMDocument()
    # sbom_doc.set_name("Clientware_ans_01")
    sbom_doc.set_metadata_version("1.7.9")
    sbom_doc.set_metadata_type("firmware")

    # sbom_doc.set_metadata_type("firmware")
    sbom.add_document(sbom_doc.get_document())

    sbom_packages = {}
    # Top Level Package
    parent_app = "ClientwareApp"
    iosapp_pkg = SBOMPackage()
    iosapp_pkg.set_name(parent_app)
    iosapp_pkg.set_version("1")
    iosapp_pkg.set_supplier("Author", "RH")
    iosapp_pkg.set_type("Application")
    iosapp_pkg.set_licensedeclared("Apache-2.0")
    parent_id = "Clientware-ans-01"
    iosapp_pkg.set_id(parent_id)
    sbom_packages[
        (iosapp_pkg.get_name(), iosapp_pkg.get_value("version"))
    ] = iosapp_pkg.get_package()

    # NordicSemi Drivers
    nsdrivers_pkg = SBOMPackage()
    nsdrivers_pkg.set_name("libnRF5.a")
    nsdrivers_pkg.set_version("17.0.2")
    nsdrivers_pkg.set_supplier("Author", "Nordic Semiconductor")
    nsdrivers_pkg.set_homepage("https://nordicsemi.com/")
    nsdrivers_pkg.set_licensedeclared("MIT")
    nsdrivers_pkg.set_id(
        nsdrivers_pkg.get_name().lower()
        + "nordicsemi@"
        + nsdrivers_pkg.get_value("version")
    )
    sbom_packages[
        (nsdrivers_pkg.get_name(), nsdrivers_pkg.get_value("version"))
    ] = nsdrivers_pkg.get_package()

    # NordicSemi Softdevice
    nssoftdev_pkg = SBOMPackage()
    nssoftdev_pkg.set_name("s140_nrf52_7.2.0_softdeviceq")
    nssoftdev_pkg.set_filename("s140_nrf52_7.2.0_softdevice.hex")
    nssoftdev_pkg.set_version("7.2.0")
    nssoftdev_pkg.set_supplier("Author", "Nordic Semiconductor")
    nssoftdev_pkg.set_homepage("https://nordicsemi.com/")
    nssoftdev_pkg.set_licensedeclared("MIT")
    nssoftdev_pkg.set_id(
        nssoftdev_pkg.get_name().lower()
        + "nordicsemi@"
        + nssoftdev_pkg.get_value("version")
    )
    sbom_packages[
        (nssoftdev_pkg.get_name(), nssoftdev_pkg.get_value("version"))
    ] = nssoftdev_pkg.get_package()

    # NordicSemi Bootloader
    nssoftdev_pkg = SBOMPackage()
    nssoftdev_pkg.set_name("ndk17.bootloader.nordicsemi")
    nssoftdev_pkg.set_type("library")
    nssoftdev_pkg.set_version("17.0.2")
    nssoftdev_pkg.set_supplier("Author", "Nordic Semiconductor")
    nssoftdev_pkg.set_homepage("https://nordicsemi.com/")
    nssoftdev_pkg.set_licensedeclared("MIT")
    nssoftdev_pkg.set_id(
        nssoftdev_pkg.get_name().lower()
        + "nordicsemi@"
        + nssoftdev_pkg.get_value("version")
    )
    sbom_packages[
        (nssoftdev_pkg.get_name(), nssoftdev_pkg.get_value("version"))
    ] = nssoftdev_pkg.get_package()

    sbom_file = SBOMFile()
    sbom_files = {}
    sbom_file.initialise()
    sbom_file.set_name("Clientware-ans-01_settings.hex")
    # sbom_file.set_filename("Clientware-ans-01_settings.hex")
    file_hash = "49108A02F3FAF3DDBFF489B2A9E0D252B7F91289"
    sbom_file.set_checksum("SHA-1", file_hash)
    # sbom_file.set_id("Hello"+sbom_file.get_name().lower())
    sbom_files[sbom_file.get_name()] = sbom_file.get_file()

    sbom.add_files(sbom_files)
    sbom.add_packages(sbom_packages)

    relationships = []
    sbom_relationship = SBOMRelationship()

    for package in sbom.get_packages():
        # Add relationship. All components are direct dependencies.
        sbom_relationship.initialise()
        if package["name"] == parent_app:
            # Parent component
            sbom_relationship.set_relationship(parent_id, "DESCRIBES", parent_app)
            sbom_relationship.set_relationship_id(None, parent_id)
        else:
            sbom_relationship.set_relationship(
                parent_app, "DEPENDS_ON", package["name"]
            )
            sbom_relationship.set_relationship_id(parent_id, package["id"])
        relationships.append(sbom_relationship.get_relationship())
    sbom.add_relationships(relationships)

    sbg = SBOMGenerator(format="tag", sbom_type="cyclonedx")

    sbg.generate(parent_id, sbom.get_sbom())
    # sbg.generate("Clientware-ans-01", sbom.get_sbom(), "mybomy-bom.json")


generate_clinician_sbom()
