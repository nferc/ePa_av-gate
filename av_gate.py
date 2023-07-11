import configparser
import email.generator
import email.parser
import email.policy
import http
import io
import logging
import os
import re
import socket
import types
from email.message import EmailMessage
from typing import List, cast
from urllib.parse import unquote, urlparse

import lxml.etree as ET
import requests
import urllib3
from flask import Flask, Response, abort, request, stream_with_context

__version__ = "1.5"

# to prevent flooding log
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
config = configparser.ConfigParser()

config.read("av_gate.ini")

loglevel = config["config"].get("log_level", "ERROR")
logging.basicConfig(
    level=loglevel, format="[%(asctime)s] %(levelname)-8s in %(module)s: %(message)s"
)
logging.info(f"av_gate {__version__}")
logging.info(f"set loglevel to {loglevel}")
logging.debug(list(config["config"].items()))

CONTENT_MAX = config["config"].getint("content_max", 800)
REMOVE_MALICIOUS = config["config"].getboolean("remove_malicious", False)
ALL_PNG_MALICIOUS = config["config"].getboolean("all_png_malicious", False)
ALL_PDF_MALICIOUS = config["config"].getboolean("all_pdf_malicious", False)


@app.route("/connector.sds", methods=["GET"])
def connector_sds():
    """replace the endpoint for PHRService with our address"""
    # <si:Service Name="PHRService">
    # <si:EndpointTLS Location="https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRService/1.3.0"/>

    client_config = get_client_config()
    with request_upstream(client_config, warn=False) as upstream:
        xml = ET.fromstring(upstream.content)

        if client_config.getboolean("proxy_all_services", False):
            for e in xml.findall("{*}ServiceInformation/{*}Service//{*}EndpointTLS"):
                previous_url = urlparse(e.attrib["Location"])
                e.attrib[
                    "Location"
                ] = f"{previous_url.scheme}://{request.host}{previous_url.path}"

        for e in xml.findall(
            "{*}ServiceInformation/{*}Service[@Name='PHRService']//{*}EndpointTLS"
        ):
            previous_url = urlparse(e.attrib["Location"])
            e.attrib[
                "Location"
            ] = f"{previous_url.scheme}://{request.host}{previous_url.path}"
        else:
            KeyError("connector.sds does not contain PHRService location.")

        return create_response(ET.tostring(xml), upstream)


@app.route("/<path:path>", methods=list(http.HTTPMethod))
def switch(path):
    """Entrypoint with filter for PHRService"""
    if "PHRService" in path:
        return phr_service(path)
    else:
        return other(path)


def phr_service(path):
    """Scan AV on xop documents for retrieveDocumentSetRequest"""
    client_config = get_client_config()
    with request_upstream(client_config) as upstream:
        data = run_antivirus(upstream)

        if not data:
            logging.info("no new body, copying content from konnektor")
            data = upstream.content

        assert (
            b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" not in data
        ), "found EICAR signature"

        response = create_response(data, upstream)

        return response


def other(path):
    """Streamed forward without scan"""
    client_config = get_client_config()
    upstream = request_upstream(client_config, stream=True)

    def generate():
        for data in upstream.iter_content():
            yield data
        upstream.close()

    response = create_response(generate, upstream)
    return response


def request_upstream(client_config, warn=True, stream=False):
    """Request to real Konnektor"""

    konn = client_config["Konnektor"]
    url = konn + request.path
    data = request.get_data()

    # client cert
    cert = None
    if client_config.get("ssl_cert"):
        cert = (client_config["ssl_cert"], client_config["ssl_key"])
    verify = client_config.getboolean("ssl_verify")

    headers = {
        key: value
        for key, value in request.headers.items()
        if key not in ("X-Real-Ip", "Host")
    }

    try:
        response = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=data,
            cert=cert,
            verify=verify,
            stream=stream,
        )

        if warn and not stream and bytes(konn, "ascii") in response.content:
            logging.warning(
                f"Found Konnektor Address in response: {konn} - {request.path}"
            )

        return response

    except Exception as err:
        logging.error(err)
        abort(502)


def get_client_config():
    request_ip = request.headers["X-real-ip"]
    port = request.host.split(":")[1] if ":" in request.host else "443"

    client = f"{request_ip}:{port}"
    logging.debug(f"client {client}")

    if config.has_section(client):
        return config[client]
    else:
        fallback = "*:" + port
        if not config.has_section(fallback):
            logging.error(f"Client {client} not found in av_gate.ini")
            abort(500)
        else:
            return config[fallback]


def create_response(data, upstream: Response) -> Response:
    """Create new response with copying headers from origin response"""
    headers = {
        k: v
        for (k, v) in upstream.headers.items()
        if k
        not in (
            "Content-Length",
            "Connection",
            "Date",
            "Transfer-Encoding",
            "Mimetype",
            "Content-Type",
        )
    }

    if type(data) is types.FunctionType:
        response = Response(
            stream_with_context(data()),
            status=upstream.status_code,
            headers=headers,
            mimetype=upstream.headers.get("Mimetype"),
            content_type=upstream.headers.get("Content-Type"),
            direct_passthrough=True,
        )
    else:
        response = Response(
            response=data,
            status=upstream.status_code,
            headers=headers,
            mimetype=upstream.headers.get("Mimetype"),
            content_type=upstream.headers.get("Content-Type"),
            direct_passthrough=True,
        )

    return response


def run_antivirus(res: requests.Response):
    """Remove document when virus was found"""

    # only interested in multipart
    if not res.headers["Content-Type"].lower().startswith("multipart"):
        return

    # add Header for content-type
    body = (
        bytes(f"Content-Type: {res.headers['Content-Type']}\r\n\r\n\r\n", "ascii")
        + res.content
    )
    msg = cast(
        EmailMessage,
        email.parser.BytesParser(policy=email.policy.default).parsebytes(body),
    )
    soap_part = cast(EmailMessage, next(msg.iter_parts()))
    xml = ET.fromstring(soap_part.get_payload())
    response_xml = xml.find("{*}Body/{*}RetrieveDocumentSetResponse")

    # only interested in RetrieveDocumentSet
    if response_xml is None:
        logging.info(f"XML NOT FOUND RetrieveDocument {soap_part.get_payload()[:200]}")
        return

    virus_atts = list(get_malicious_content_ids(msg))

    if virus_atts:
        xml_resp = response_xml.find("{*}RegistryResponse")
        assert xml_resp is not None
        m = re.search("{.*}", xml_resp.tag)
        assert m
        xml_ns = m[0]

        # ger errlist
        xml_errlist = xml_resp.find("{*}RegistryErrorList")
        if not xml_errlist:
            xml_errlist = ET.Element(f"{xml_ns}RegistryErrorList")
            xml_resp.append(xml_errlist)

        xml_documents = {}

        for doc in response_xml.findall("{*}DocumentResponse"):
            include = doc.find("{*}Document/{*}Include")
            assert include is not None
            href = cast(str, include.attrib["href"])
            assert href
            content_id = extract_id(href)
            xml_documents[content_id] = doc

        logging.debug(f"content_ids: {list(xml_documents.keys())}")

        attachments = cast(List[EmailMessage], list(msg.iter_attachments()))
        msg.set_payload([soap_part])
        for att in attachments:
            handle_attachment(
                msg, response_xml, virus_atts, xml_ns, xml_errlist, xml_documents, att
            )

        if REMOVE_MALICIOUS:
            fix_status(xml_resp, xml_errlist, xml_ns, msg)

    if virus_atts:
        if REMOVE_MALICIOUS:
            soap_part.set_payload(ET.tostring(xml), charset="utf-8")
            del soap_part["MIME-Version"]

        payload = build_payload(msg, virus_atts, res)

        return payload


def handle_attachment(
    msg, response_xml, virus_atts, xml_ns, xml_errlist, xml_documents, att
):
    """removes or replaces malicious attachment"""
    content_id = extract_id(att["Content-ID"])
    document_xml = xml_documents[content_id]
    unique_id_xml = document_xml.find("{*}DocumentUniqueId")
    assert unique_id_xml is not None
    document_id = unique_id_xml.text
    mimetype_xml = document_xml.find("{*}mimeType")
    assert mimetype_xml is not None
    mimetype = mimetype_xml.text

    if content_id in virus_atts:
        if REMOVE_MALICIOUS:
            add_error_msg(document_xml, xml_errlist, xml_ns)
            # remove document reference
            response_xml.remove(document_xml)
            logging.info(f"document removed {content_id!r} {document_id!r}")

        else:
            # replace document
            logging.info(
                f"document replaced {content_id!r} {document_id!r} {mimetype!r}"
            )
            att.set_payload(get_replacement(mimetype))
            msg.attach(att)
    else:
        logging.debug(f"document untouched {content_id!r} {document_id!r}")
        msg.attach(att)


def get_malicious_content_ids(msg):
    """Extracting content_ids of malicious attachments"""
    for att in msg.iter_attachments():
        scan_res = scan_file(att.get_content())
        content_id = extract_id(att["Content-ID"])

        test_malicous = False
        if ALL_PNG_MALICIOUS and att.get_content().startswith(
            bytearray.fromhex("89504E470D0A1A0A")
        ):
            test_malicous = True
        if ALL_PDF_MALICIOUS and att.get_content().startswith(
            bytearray.fromhex("25504446")
        ):
            test_malicous = True

        if scan_res[0] != "OK" or test_malicous:
            logging.info(f"virus found {content_id} : {scan_res}")
            yield content_id
        else:
            logging.info(f"scanned document {content_id} : {scan_res}")
            if b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in att.get_content():
                logging.error(f"EICAR was not detected by clamav {content_id}")


def extract_id(id: str) -> str:
    """Returns content_id without prefix and postfix"""
    id = unquote(id)

    if id.startswith("cid:"):
        id = id[4:]
    if id.startswith("<"):
        id = id[1:-1]
    if "@" in id:
        id = id[: id.index("@")]

    return id


def add_error_msg(document_id, xml_errlist, xml_ns):
    """Adds error message to SOAP message for given document"""
    err_text = f"Document was detected as malware for uniqueId '{document_id}'."
    xml_errlist.append(
        ET.Element(
            f"{xml_ns}RegistryError",
            attrib={
                "codeContext": err_text,
                "errorCode": "XDSDocumentUniqueIdError",  # from RetrieveDocumentSetResponse
                # "errorCode": "XDSMissingDocument", # from AdHocQueryResponse
                "severity": "urn:oasis:names:tc:ebxml-regrep:ErrorSeverityType:Error",
            },
            text=err_text,
        )
    )


def fix_status(xml_resp, xml_errlist, xml_ns, msg):
    """Adds overall error message to SOAP response"""
    if len(msg.get_payload()) > 1:
        xml_resp.attrib["status"] = "urn:ihe:iti:2007:ResponseStatusType:PartialSuccess"
    else:
        xml_resp.attrib[
            "status"
        ] = "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Failure"
        xml_errlist.append(
            ET.Element(
                f"{xml_ns}RegistryError",
                attrib={
                    "severity": "urn:oasis:names:tc:ebxml-regrep:ErrorSeverityType:Error",
                    "errorCode": "XDSRegistryMetadataError",
                    "codeContext": "No documents found for unique ids in request",
                },
                text="No documents found for unique ids in request",
            )
        )


def build_payload(msg: EmailMessage, virus_atts: List[str], res: requests.Response):
    "create payload based on original response with replacing only payoad for virus_atts"

    content_type = res.headers["Content-Type"]
    m = re.search('boundary="(.*?)"', content_type, re.I)
    assert m
    boundary = b"\r\n--" + bytes(m[1], "ascii")

    payload: List[bytes] = []
    for part in res.content.split(boundary):
        content_id = get_content_id(part)
        if (
            content_id in virus_atts
            or content_id == "root.message"
            and REMOVE_MALICIOUS
        ):
            att = cast(
                EmailMessage,
                next(
                    (
                        a
                        for a in msg.iter_parts()
                        if content_id == extract_id(a.get("Content-ID", ""))
                    ),
                    None,
                ),
            )
            if att:
                content = att.get_content()
                payload.append(part.split(b"\r\n\r\n")[0] + b"\r\n\r\n" + content)
            else:
                logging.error(
                    f"Content-ID not present: {content_id} in {next(msg.iter_parts()).items()}"
                )

        else:
            payload.append(part)

    return boundary.join(payload)


def get_content_id(content: bytes):
    m = re.search(b"\r\nContent-ID: (.*?)\r\n", content, re.I)
    if m:
        return extract_id(m[1].decode("ascii"))


# create dictonary with mimetypes: filename
replacement_files = {
    os.path.splitext(dir_entry.name)[0].replace("_", "/"): dir_entry.path
    for dir_entry in os.scandir("replacements")
}


def get_replacement(mimetype):
    """get content for replacements"""
    filename = replacement_files.get(mimetype) or replacement_files.get("text/plain")
    with open(filename, "rb") as f:
        return f.read()


def dump(dict):
    return "\n".join([f"{k}: {v}" for (k, v) in dict.items()])

# File Scanning

def get_file_scanner():
    clamd_path = config["config"].get("clamd_socket")
    global icap_host
    icap_host = config["config"].get("icap_host")

    if not clamd_path and not icap_host:
        raise AttributeError("Neither clamd nor icap is configured")
    if clamd_path and icap_host:
        raise AttributeError("Both, clamd and icap is configured")
    
    if clamd_path:
        import clamd  # type: ignore
        global clamav_sock
        clamav_sock = clamd.ClamdUnixSocket(
            path=config["config"]["clamd_socket"])
        return scan_file_clamav
    else:
        # ICAP
        global icap_port
        icap_port = config["config"].get("icap_port", 1344)
        global icap_service
        icap_service = config["config"]["icap_service"]
        return scan_file_icap

def scan_file_clamav(content):
    "return scan result, do use clamav socket"
    scan_res = clamav_sock.instream(io.BytesIO(content))["stream"]
    return scan_res
    
def scan_file_icap(content):
    "return scan result, do use icap"                
    req = f"RESPMOD {icap_service} ICAP/1.0\r\n"
    req += f"Host: {icap_host}\r\n"
    req += f"Encapsulated: res-body=0\r\n\r\n"
    req += f"{len(content):x}\r\n"

    footer = "\r\n0\r\n\r\n"

    rcv_chunks = []

    with socket.create_connection((icap_host, icap_port)) as sock:
        sock.send(req.encode())
        sock.sendall(content)
        sock.send(footer.encode())
    
        while True:
            data = sock.recv(4096)
            rcv_chunks.append(data)
            if (not len(data) or data[-5:] == b"0\r\n\r\n"):
                break

    rsp = b''.join(rcv_chunks)[:2048]

    first_block = rsp.partition(b"\r\n\r\n")[0]
    first_line = first_block.partition(b'\r\n')[0]

    logging.debug(first_block)

    if first_line != b"ICAP/1.0 200 OK":
        raise EnvironmentError("ICAP not OK", first_line)

    # this might differ on other icap servers
    found = re.search(b"X-Infection-Found: .*Threat=(.*);", first_block)    
    if found:
        return ["FOUND", found[1]]

    return ["OK", None]

scan_file = get_file_scanner()


if __name__ == "__main__":
    # only relevant, when started directly.
    # production runs uwsgi
    app.run(host="0.0.0.0", debug=True, port=5001)
