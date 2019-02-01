# -*- coding: UTF-8 -*-
"""
   Copyright 2019 Esri

   Licensed under the Apache License, Version 2.0 (the "License");

   you may not use this file except in compliance with the License.

   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software

   distributed under the License is distributed on an "AS IS" BASIS,

   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

   See the License for the specific language governing permissions and

   limitations under the License.​

    This sample copies/upgrades a project
"""
import tempfile
import argparse
import logging
import logging.handlers
import traceback
import sys
import arcgis
import copy
from arcgis.apps import workforce
from arcgis.gis import GIS


def initialize_logging(log_file):
    """
    Setup logging
    :param log_file: (string) The file to log to
    :return: (Logger) a logging instance
    """
    # initialize logging
    formatter = logging.Formatter("[%(asctime)s] [%(filename)30s:%(lineno)4s - %(funcName)30s()]\
             [%(threadName)5s] [%(name)10.10s] [%(levelname)8s] %(message)s")
    # Grab the root logger
    logger = logging.getLogger()
    # Set the root logger logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    logger.setLevel(logging.DEBUG)
    # Create a handler to print to the console
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    sh.setLevel(logging.INFO)
    # Create a handler to log to the specified file
    rh = logging.handlers.RotatingFileHandler(log_file, mode='a', maxBytes=10485760)
    rh.setFormatter(formatter)
    rh.setLevel(logging.DEBUG)
    # Add the handlers to the root logger
    logger.addHandler(sh)
    logger.addHandler(rh)
    return logger


def main(arguments):
    logger = initialize_logging(arguments.log_file)
    logger.info("Authenticating...")
    gis = GIS(arguments.org_url,
              username=arguments.username,
              password=arguments.password,
              verify_cert=not arguments.skip_ssl_verification)

    item = gis.content.get(arguments.project_id)
    project = workforce.Project(item)

    logger.info("Creating New Project...")
    upgraded_project = arcgis.apps.workforce.create_project(
        "{} - Upgraded".format(project.title),
        project.summary
    )

    # copy over assignment types
    logger.info("Copying Assignment Types...")
    upgraded_project.assignment_types.batch_add(project.assignment_types.search())

    logger.info("Copying App Integrations...")
    upgraded_project.integrations.batch_delete([upgraded_project.integrations.get("default-navigator")])
    upgraded_project.integrations.batch_add(project.integrations.search())

    logger.info("Copying Workers...")
    workers = {w.global_id: {"source": w.feature, "target": copy.deepcopy(w.feature)} for w in project.workers.search()}
    dispatchers = {d.global_id: {"source": d.feature, "target": copy.deepcopy(d.feature)} for d in project.dispatchers.search()}

    results = upgraded_project.workers_layer.edit_features(
        adds=[w["target"] for w in workers.values()],
        use_global_ids=True
    )
    for res in results["addResults"]:
        if res["success"]:
            workers[res["globalId"]]["target"].attributes[upgraded_project._worker_schema.object_id] = res["objectId"]
        else:
            raise Exception("Failed to add workers")

    logger.info("Copying Dispatchers...")
    results = upgraded_project.dispatchers_layer.edit_features(
        adds=[d["target"] for d in dispatchers.values() if d["target"].attributes[upgraded_project._dispatcher_schema.user_id] != gis.users.me.username],
        use_global_ids=True
    )
    for res in results["addResults"]:
        if res["success"]:
            dispatchers[res["globalId"]]["target"].attributes[upgraded_project._dispatcher_schema.object_id] = res["objectId"]
        else:
            raise Exception("Failed to add dispatchers")
    usernames = [w["source"].attributes[upgraded_project._worker_schema.user_id] for w in workers.values()]
    usernames.extend([w["source"].attributes[upgraded_project._dispatcher_schema.user_id] for w in dispatchers.values()])
    upgraded_project.group.add_users(set(usernames))

    # copy over assignments
    logger.info("Copying Assignments...")
    assignments = {a.global_id: {"source": a.feature, "target": copy.deepcopy(a.feature)} for a in project.assignments.search()}
    worker_mapping = {w["source"].attributes[upgraded_project._worker_schema.object_id]: w["target"].attributes[upgraded_project._worker_schema.object_id] for w in workers.values()}
    dispatcher_mapping = {w["source"].attributes[upgraded_project._dispatcher_schema.object_id]: w["target"].attributes[upgraded_project._dispatcher_schema.object_id] for w in dispatchers.values()}
    # swizzle worker and dispatcher ids
    for a in assignments.values():
        a["target"].attributes[upgraded_project._assignment_schema.worker_id] = worker_mapping.get(a["source"].attributes[upgraded_project._assignment_schema.worker_id], None)
        a["target"].attributes[upgraded_project._assignment_schema.dispatcher_id] = dispatcher_mapping.get(a["source"].attributes[upgraded_project._assignment_schema.dispatcher_id])
        a["target"].attributes.pop(upgraded_project._assignment_schema.assignment_read, None)
    results = upgraded_project.assignments_layer.edit_features(
        adds=[a["target"] for a in assignments.values()],
        use_global_ids=True
    )
    for res in results["addResults"]:
        if res["success"]:
            assignments[res["globalId"]]["target"].attributes[upgraded_project._assignment_schema.object_id] = res["objectId"]
        else:
            raise Exception("Failed to add assignments")
    assignment_mapping = {a["source"].attributes[upgraded_project._assignment_schema.object_id]: a["target"].attributes[upgraded_project._assignment_schema.object_id] for a in assignments.values()}

    logger.info("Copying Attachments...")
    attachments = project.assignments_layer.attachments.search()
    for a in attachments:
        with tempfile.TemporaryDirectory() as dirpath:
            paths = project.assignments_layer.attachments.download(a['PARENTOBJECTID'], a['ID'], dirpath)
            upgraded_project.assignments_layer.attachments.add(
                assignment_mapping[a['PARENTOBJECTID']],
                paths[0]
            )

    # TODO
    # copy webmap layers
    # need to skip existing WF layers

    logger.info("Completed")


if __name__ == "__main__":
    # Get all of the commandline arguments
    parser = argparse.ArgumentParser("Export assignments from Workforce Project")
    parser.add_argument('-u', dest='username', help="The username to authenticate with", required=True)
    parser.add_argument('-p', dest='password', help="The password to authenticate with", required=True)
    parser.add_argument('-org', dest='org_url', help="The url of the org/portal to use", required=True)
    # Parameters for workforce
    parser.add_argument('-project-id', dest='project_id', help="The id of the project to delete assignments from",
                        required=True)
    parser.add_argument('-log-file', dest='log_file', help="The log file to write to", required=True)
    parser.add_argument('--skip-ssl-verification', dest='skip_ssl_verification', action='store_true',
                        help="Verify the SSL Certificate of the server")
    args = parser.parse_args()
    try:
        main(args)
    except Exception as e:
        logging.getLogger().critical("Exception detected, script exiting")
        logging.getLogger().critical(e)
        logging.getLogger().critical(traceback.format_exc().replace("\n", " | "))
