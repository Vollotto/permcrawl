def format_analysis_dict(analysis_data):
    # Dummy for app analysis dict
    app_dict = dict()
    app_dict.update({"app_name": analysis_data["app_name"],
                     "package_name": analysis_data["package_name"],
                     "target_sdk": analysis_data["target_sdk"],
                     "target_sdk_too_low": analysis_data["target_sdk_too_low"],
                     "no_permission": analysis_data["no_permission"],
                     "error": analysis_data["error"],
                     "declared_permissions": analysis_data["permissions_from_manifest"]})

    # Dummies for detailed permission analysis dicts
    for permission in app_dict["declared_permissions"]:
        perm_dict = {
            permission: {
                "up_front": False,
                "in_context": False,
                "educated": False,
                "requests": [],
                "usages": [],
                "#requests_w_backtrace": 0,
                "#requests_w_explanation": 0,
                "#usages_w_backtrace": 0
            }
        }
        app_dict.update(perm_dict)

    return app_dict


def format_requests(analysis_data, app_dict):
    for request in analysis_data["analyzed_requests"]:
        # Skip Unknown Permissions as they do not count for final evaluation
        if request["permission"] == "Unknown Permission":
            continue

        app_dict[request["permission"]]["requests"].append(
            {
                # original analysis data is formatted in an androguard-optimized manner
                # change it in a way such that we have a simple string reqpresenting a method
                #     {class_name}->{method_name}{descriptor} [access_flags={access_flags}]
                "location": "%s->%s%s [access_flags=%s]" % (request["method"]["class_name"],
                                                            request["method"]["name"],
                                                            request["method"]["descriptor"],
                                                            request["method"]["access_flags"]),
                "caller": "%s->%s%s [access_flags=%s]" % (request["caller"]["class_name"],
                                                          request["caller"]["name"],
                                                          request["caller"]["descriptor"],
                                                          request["caller"]["access_flags"]),
                # if the backtrace path is not empty we convert it into string representations separated by ';'
                "backtrace": ("; ".join(["{0}->{1}{2} [access_flags={3}]".
                                       format(node["class_name"], node["name"],
                                              node["descriptor"], node["access_flags"])
                                        for node in request["path"]])) if request["path"] else [],
                "explanations": request["explanation"]
            }
        )

        # We have a request that was succesfully backtraced
        if request["path"]:
            app_dict[request["permission"]]["up_front"] = True
            app_dict[request["permission"]]["#requests_w_backtrace"] += 1

            # Now check whether it is also educated
            if request["explanation"]:
                app_dict[request["permission"]]["educated"] = True
                app_dict[request["permission"]]["#requests_w_explanation"] += 1

        else:
            # We found an explanation
            if request["explanation"]:
                app_dict[request["permission"]]["#requests_w_explanation"] += 1

    # Now we checked whether there was any explanation but no backtrace
    for perm in app_dict["declared_permissions"]:
        if (not app_dict[perm]["up_front"]) and app_dict[perm]["#requests_w_explanation"] > 0:
            app_dict[perm]["educated"] = True

    return app_dict


def format_usages(analysis_data, app_dict):
    for usage in analysis_data["analyzed_usages"]:
        # Skip Unknown Permissions as they do not count for final evaluation
        if usage["permission"] == "Unknown Permission":
            continue

        app_dict[usage["permission"]]["usages"].append(
            {
                "location": "%s->%s%s [access_flags=%s]" % (usage["method"]["class_name"],
                                                            usage["method"]["name"],
                                                            usage["method"]["descriptor"],
                                                            usage["method"]["access_flags"]),
                "backtrace": (";".join(["{0}->{1}{2} [access_flags={3}]".
                                       format(node["class_name"], node["name"],
                                              node["descriptor"], node["access_flags"])
                                        for node in usage["path"]])) if usage["path"] else [],
            }
        )

        if usage["path"]:
            if not app_dict[usage["permission"]]["up_front"]:
                app_dict[usage["permission"]]["in_context"] = True
            app_dict[usage["permission"]]["#usages_w_backtrace"] += 1

    return app_dict


def format_single_analysis(analysis_data):
    formatted_data = format_analysis_dict(analysis_data=analysis_data)
    formatted_data = format_requests(analysis_data=analysis_data, app_dict=formatted_data)
    return format_usages(analysis_data=analysis_data, app_dict=formatted_data)
