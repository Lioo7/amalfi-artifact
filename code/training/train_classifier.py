#! /usr/bin/env python3

import argparse
import csv
import os
import pickle
import random
import logging

from datetime import timedelta
from graphviz import Source
from sklearn import tree
from sklearn import naive_bayes
from sklearn import svm
from sklearn.ensemble import RandomForestClassifier
from timeit import default_timer as timer
from util import parse_date, version_date

LOGֹ_FORMAT = "%(levelname)s, time: %(asctime)s , line: %(lineno)d- %(message)s "
# create and configure logger
logging.basicConfig(
    filename="ftrain-classifier-logging.log", level=logging.INFO, filemode="w"
)
logger = logging.getLogger()

# features with continuous values
CONTINUOUS_FEATURES = ["entropy average", "entropy standard deviation", "time"]


def train_classifier(classifier, malicious_path, training_sets, output, booleanize=False, hashing=False, exclude_features=None,
                     nu=0.001, positive=False, render=False, randomize=False, view=False, leave_out=None, until=None, performance=None):
    """
    Train a classifier using the specified parameters.

    classifier: str
        The type of classifier to use. One of: "decision-tree", "naive-bayes", "support-vector-machine", or "random-forest".
    malicious_path: str
        The file path to a CSV file containing known malicious packages and versions or their hashes.
    training_sets: list of str
        A list of directories containing training sets.
    output: str
        The file path to save the trained classifier to.
    booleanize: bool, optional
        Whether to convert continuous values to binary values (True) or not (False). Default is False.
    hashing: bool, optional
        Whether to use hashes instead of package and version names. Default is False.
    exclude_features: list of str, optional
        A list of features to exclude from the classifier. Default is None.
    nu: float, optional
        The value of nu to use for SVM. Default is 0.001.
    positive: bool, optional
        Whether to use only positive feature values. Default is False.
    render: bool, optional
        Whether to render a visualization of the decision tree. Default is False.
    randomize: bool, optional
        Whether to randomize the labels of the training set. Default is False.
    view: bool, optional
        Whether to display the visualization of the decision tree. Default is False.
    leave_out: list of str, optional
        A list of directories to leave out of the training set. Default is None.
    until: str, optional
        Only include training examples from before this date. Default is None.
    performance: str, optional
        File path to save performance results. Default is None.
    """
    logging.info("start func: train_classifier")
    
    if exclude_features == None:
        exclude_features = []

    if leave_out == None:
        leave_out = []

    # Naive Bayes implicitly booleanizes the feature vectors
    if classifier == "naive-bayes":
        booleanize = True

    # exclude continuous features when booleanizing
    if booleanize:
        exclude_features.extend(CONTINUOUS_FEATURES)

    # names of features
    feature_names = []
    # an array of arrays, each of which is a feature vector
    training_set = []
    # label each row of the feature matrix as either "benign" or "malicious"
    labels = []

    # load known malicious (package,version) pairs or their hashes
    malicious = set()
    with open(malicious_path, "r") as mal:
        reynolds = csv.reader(mal)
        for row in reynolds:
            if hashing:
                hash_res = row[0]
                malicious.add(hash_res)
            else:
                package, version = row
                malicious.add((package, version))

    # if randomize is on, we track the size of the malicious class length
    if randomize:
        malicious_len = 0

    versions = {}
    # versions = {'2450yuanzhik': {'1.0.0': '2022-03-12T20:12:15.998447Z'}, '@atos6/a6-shortcuts': {'0.0.11-alpha': '2023-01-17T20:12:15.998617Z'}, '@aviationpast/niotest': {'1.0.17': '2022-05-22T20:12:15.998150Z'}, '@aws-amplify/core': {'4.7.13': '2022-05-28T20:12:15.998279Z'}, '@cloudflare/intl-react': {'1.9.137': '2022-05-10T20:12:15.998580Z'}, '@cloudflare/types': {'6.19.5': '2022-09-18T20:12:15.998584Z'}, '@cronvel/ms-kit': {'0.1.2': '2022-11-17T20:12:15.998576Z'}, '@domoskanonos/workboy': {'1.0.23': '2022-03-31T20:12:15.998166Z'}, '@farfetch/blackout-react': {'0.47.1': '2022-05-15T20:12:15.998392Z'}, '@getsynapse/design-system': {'4.14.1-2': '2022-06-04T20:12:15.998638Z'}, '@gravity-ui/app-builder': {'0.0.2': '2022-10-25T20:12:15.998630Z'}, '@gun-vue/composables': {'0.12.0': '2022-11-26T20:12:15.998225Z'}, '@m3hul/web-pkg': {'1.0.0': '2022-09-12T20:12:15.998497Z'}, '@mrfakename/eazyminer': {'0.1.19': '2022-06-25T20:12:15.998355Z'}, '@mrfakename/multiminer': {'0.1.10': '2022-03-25T20:12:15.998351Z'}, '@productplan/atlas-tokens': {'0.1.0': '2022-05-05T20:12:15.998380Z'}, '@prutech/referrals': {'1.0.18': '2022-03-06T20:12:15.998572Z'}, '@tranzit/front-notes': {'1.0.5': '2022-07-27T20:12:15.998275Z'}, '@tybalt/validator': {'0.0.8': '2022-06-09T20:12:15.998426Z'}, '@worldsky/weather': {'1.0.2': '2022-04-19T20:12:15.998200Z'}, 'aevgenij_psca6': {'1.0.1': '2022-08-22T20:12:15.998513Z'}, 'appdynamics-native': {'1.1.1': '2022-07-04T20:12:15.998522Z'}, 'atm-by-frank': {'1.2.0': '2023-02-09T20:12:15.998388Z'}, 'bdmp-ui': {'2.2.5': '2022-06-16T20:12:15.998196Z'}, 'chromecast-client': {'1.0.0': '2023-02-11T20:12:15.998175Z'}, 'clevy-test': {'0.1.0': '2022-05-16T20:12:15.998430Z'}, 'cmfx-dashboard': {'0.5.0': '2022-03-23T20:12:15.998605Z'}, 'codezist': {'1.0.0': '2022-12-20T20:12:15.998208Z'}, 'commitri': {'1.0.2': '2022-08-16T20:12:15.998204Z'}, 'component-modal': {'0.1.5': '2022-06-27T20:12:15.998588Z'}, 'cornsol': {'1.0.2': '2022-07-08T20:12:15.998451Z'}, 'cors-2.8.5': {'2.8.5': '2022-05-31T20:12:15.998044Z'}, 'cors.js': {'2.8.5': '2022-02-18T20:12:15.998037Z'}, 'create-ibl-app': {'0.2.5': '2022-12-13T20:12:15.998263Z'}, 'cruwi-widget-staging': {'1.0.0': '2022-10-04T20:12:15.998555Z'}, 'cuon-matrix': {'0.3.1': '2022-08-24T20:12:15.998601Z'}, 'cute-free-tiktok-fans-and-likes-booster-2022': {'1.0.0': '2023-01-04T20:12:15.998137Z'}, 'cute-free-tiktok-followers-and-likes-booster-2022': {'1.0.0': '2022-12-25T20:12:15.998304Z'}, 'cyb-core': {'9.9.9': '2022-08-19T20:12:15.998158Z'}, 'database-context-pg': {'0.0.5': '2023-01-25T20:12:15.998384Z'}, 'debug-common': {'1.1.1': '2022-05-08T20:12:15.998090Z'}, 'demo-easy-code': {'0.1.124': '2022-03-09T20:12:15.998288Z'}, 'dev-wallet': {'99.9.9': '2022-03-07T20:12:15.998463Z'}, 'easy-tailwind': {'1.0.0': '2023-01-09T20:12:15.998405Z'}, 'easy-waf': {'0.3.1': '2022-07-24T20:12:15.998221Z'}, 'element-via': {'2.1.12': '2022-05-23T20:12:15.998187Z'}, 'eslint-config-opentable-es5': {'1.1.1': '2022-08-19T20:12:15.998363Z'}, 'eslint-plugin-automation-custom': {'19.0.0': '2022-04-16T20:12:15.998054Z'}, 'evil-npm-packagee': {'1.0.3': '2023-02-04T20:12:15.998133Z'}, 'flow-bin': {'0.196.1': '2022-09-05T20:12:15.998409Z'}, 'gallery-web': {'1.0.0': '2022-09-28T20:12:15.998501Z'}, 'get-free-cash-app-money': {'1.0.0': '2022-12-10T20:12:15.998141Z'}, 'gis3d': {'1.0.6': '2022-08-28T20:12:15.998192Z'}, 'globalshut': {'1.0.0': '2022-08-11T20:12:15.998171Z'}, 'gramin-chat1': {'1.0.0': '2023-01-04T20:12:15.998342Z'}, 'handle-sdk': {'0.5.8': '2022-07-09T20:12:15.998250Z'}, 'imask-module': {'0.0.3': '2022-04-16T20:12:15.998229Z'}, 'imongo': {'1.0.11': '2022-04-11T20:12:15.998292Z'}, 'internal-lib-build': {'2.4.1-dev': '2022-08-27T20:12:15.998538Z'}, 'ipcode': {'7.0.0': '2022-12-09T20:12:15.998472Z'}, 'islands-specific': {'137.0.0': '2022-11-28T20:12:15.998376Z'}, 'jfrog-cli-v2': {'2.31.0': '2022-10-10T20:12:15.998259Z'}, 'kikeappa': {'1.0.2': '2022-07-26T20:12:15.998517Z'}, 'koishi-plugin-rsshub': {'0.0.3': '2022-02-13T20:12:15.998183Z'}, 'laravel-vue-i18n': {'2.3.2': '2022-03-08T20:12:15.998418Z'}, 'likeappa': {'1.0.3': '2022-04-30T20:12:15.998154Z'}, 'likesec': {'1.0.2': '2022-06-21T20:12:15.998313Z'}, 'likesecapp': {'1.0.2': '2022-04-22T20:12:15.998309Z'}, 'market-apps-list': {'0.0.0': '2022-11-14T20:12:15.998094Z'}, 'mihail6labm0603': {'1.0.0': '2022-03-08T20:12:15.998367Z'}, 'niodependencytest': {'1.0.2': '2022-03-15T20:12:15.998145Z'}, 'node-debug-service': {'1.0.0': '2022-09-04T20:12:15.998484Z'}, 'node-monero-miner': {'0.2.4': '2022-06-21T20:12:15.998359Z'}, 'notar-cli': {'1.2.1': '2022-05-18T20:12:15.998238Z'}, 'notify-qq': {'0.0.2': '2022-12-04T20:12:15.998217Z'}, 'nutritionix-api-data-utilities': {'2.12.0': '2022-07-07T20:12:15.998559Z'}, 'oel-ng-translate-loaders': {'1.0.0': '2022-11-26T20:12:15.998489Z'}, 'oel-ng-ui': {'1.0.0': '2022-09-29T20:12:15.998493Z'}, 'openfin-notifications': {'1.19.0': '2023-02-04T20:12:15.998563Z'}, 'packyourbag': {'9.9.9': '2022-12-13T20:12:15.998116Z'}, 'panel-shared': {'0.0.36': '2022-09-14T20:12:15.998212Z'}, 'payload': {'1.1.3': '2022-05-13T20:12:15.998234Z'}, 'paysafecard-payout': {'7.0.7': '2022-02-17T20:12:15.998509Z'}, 'peter-parker-spider-man-no-way-home-2021-online': {'2.0.0': '2022-11-16T20:12:15.998371Z'}, 'pia6-4': {'1.1.1': '2023-01-03T20:12:15.998162Z'}, 'plan-r-icons': {'1.4.2': '2022-11-11T20:12:15.998634Z'}, 'praxar-coreapi': {'2.3.0': '2022-12-11T20:12:15.998626Z'}, 'prisma': {'4.8.0-dev.66': '2022-04-25T20:12:15.998642Z'}, 'pt03-package': {'1.0.4': '2022-12-05T20:12:15.998459Z'}, 'pt03-sub-package': {'1.0.0': '2022-11-10T20:12:15.998468Z'}, 'quontral': {'1.0.16': '2022-11-25T20:12:15.998179Z'}, 'real-free-tiktok-fans-likes-and-followers-2022': {'1.0.0': '2022-10-10T20:12:15.998347Z'}, 'redeem-free-cash-app-money': {'1.0.0': '2022-10-25T20:12:15.998300Z'}, 'redux-obey': {'0.0.12-alpha': '2022-02-23T20:12:15.998613Z'}, 'redzone': {'3.0.0': '2022-09-19T20:12:15.998099Z'}, 'rimg-shopify': {'88.9.9': '2022-12-12T20:12:15.998505Z'}, 'route-event': {'4.1.6': '2022-10-17T20:12:15.998439Z'}, 'saferme-ui-react': {'1.0.1-0': '2022-02-16T20:12:15.998455Z'}, 'saucectl': {'0.117.0': '2022-07-19T20:12:15.998593Z'}, 'sciola': {'1.0.5': '2022-03-16T20:12:15.998284Z'}, 'sdk-api': {'2.0.0': '2022-03-10T20:12:15.997993Z'}, 'sdk-coin-bch': {'2.0.0': '2022-05-03T20:12:15.998049Z'}, 'securityrele': {'0.0.8': '2022-05-11T20:12:15.998081Z'}, 'shortkut': {'0.5.1': '2022-08-17T20:12:15.998597Z'}, 'smev3-soap': {'1.0.1': '2023-02-10T20:12:15.998647Z'}, 'sock-1': {'1.0.3': '2022-11-13T20:12:15.998547Z'}, 'sock-2': {'1.0.2': '2022-11-13T20:12:15.998326Z'}, 'socket-first-level-dep-1': {'1.0.0': '2022-04-25T20:12:15.998330Z'}, 'socket-test-vulnerable': {'1.0.2': '2023-01-31T20:12:15.998551Z'}, 'sofa1-shop': {'9.9.9': '2022-02-15T20:12:15.998112Z'}, 'solid-rewind': {'0.0.2': '2022-05-31T20:12:15.998622Z'}, 'sportlifejs': {'1.1.2': '2022-03-12T20:12:15.998338Z'}, 'stale-props': {'0.0.2': '2022-07-19T20:12:15.998334Z'}, 't0604nodule': {'1.0.1': '2022-10-31T20:12:15.998128Z'}, 't3dcar': {'1.1.0': '2022-05-22T20:12:15.998086Z'}, 'tes1a': {'9.9.3': '2022-08-12T20:12:15.998526Z'}, 'test-draco': {'0.0.1': '2022-07-28T20:12:15.998476Z'}, 'test-inherited-attrs': {'1.0.0': '2022-06-18T20:12:15.998543Z'}, 'test-package-dependencyconfusion': {'1.0.4': '2022-02-25T20:12:15.998059Z'}, 'test1221-npm': {'1.0.0': '2022-05-16T20:12:15.998317Z'}, 'testername': {'1.4.11': '2022-12-20T20:12:15.998321Z'}, 'testherejson': {'1.0.11': '2022-08-30T20:12:15.998077Z'}, 'testing-roundpe-sdk': {'0.0.3': '2022-09-13T20:12:15.998267Z'}, 'timp-validate': {'1.0.7': '2022-09-16T20:12:15.998567Z'}, 'touching-fish': {'0.0.1': '2022-12-28T20:12:15.998072Z'}, 'ts-interpreter.js': {'1.0.1': '2022-07-29T20:12:15.998413Z'}, 'uicore-ts': {'1.0.87': '2023-01-24T20:12:15.998434Z'}, 'ul-mailru': {'13.2.3': '2022-09-02T20:12:15.998534Z'}, 'upload-image-plugin': {'3.0.0': '2022-12-29T20:12:15.998255Z'}, 'vanshpkg': {'2.0.0': '2022-11-24T20:12:15.998068Z'}, 'vanshpkgg': {'2.0.0': '2022-07-16T20:12:15.998063Z'}, 'vo-core': {'1.2.3': '2022-06-28T20:12:15.998271Z'}, 'voidkit': {'0.0.17': '2022-11-26T20:12:15.998246Z'}, 'volvo-autopilot.': {'2.0.0': '2022-11-21T20:12:15.998480Z'}, 'wf-grunt': {'7.0.7': '2022-02-12T20:12:15.998530Z'}, 'who_ask': {'9.9.9': '2022-07-11T20:12:15.998107Z'}, 'ws-ui-tool': {'19.0.0': '2022-07-05T20:12:15.998124Z'}, 'xfinityhome': {'2.1.0': '2022-02-25T20:12:15.998609Z'}, 'xterm-addon-serialize': {'0.9.0': '2022-11-09T20:12:15.998397Z'}, 'yeap': {'1.3.0-beta.1': '2022-12-31T20:12:15.998443Z'}, 'yf_hello_world': {'1.0.4': '2022-07-13T20:12:15.998120Z'}, 'ysfoxx': {'1.999.99': '2022-09-25T20:12:15.998103Z'}, 'ysofx': {'1.999.99': '2022-07-07T20:12:15.998296Z'}, 'zenstack': {'0.5.0': '2022-09-03T20:12:15.998242Z'}}
    
    # find all `change-features.csv` files in all training_set directories
    for training_set_dir in training_sets:
        for root, _, files in os.walk(training_set_dir):
            for f in files:
                if f == "change-features.csv" and f"{root}" not in leave_out:
                    package = os.path.relpath(os.path.dirname(root), training_set_dir)
                    logger.info(f"training_set_dir: {training_set_dir}")
                    logging.info(f'os.path.dirname(root): {os.path.dirname(root)}')
                    logging.info(f"package: {package}")
                    version = os.path.basename(root)
                    logging.info(f"version: {version}")
                    date = version_date(versions, root)
                    print(f"{package}@{version}: {date}")
                    logging.info(f"package@version:date -> {package}@{version}: {date}")
                    if until is not None and date >= until:
                        print(f"Skipping {package}@{version}. Date {date} is outside the boundaries.")
                        logging.warning(f"Skipping {package}@{version}. Date {date} is outside the boundaries.")
                        continue

                    print(f"Processing {package}@{version}")
                    # load features for this package
                    with open(os.path.join(root, f), "r") as feature_file:
                        logging.info(f"feature_file: {os.path.join(root, f)}")
                        # first, read features into a dictionary
                        feature_dict = {}
                        for row in csv.reader(feature_file):
                            feature, value = row
                            value = float(value)

                            if positive and value < 0:
                                value = 0
                            if booleanize:
                                value = 1 if value > 0 else 0
                            if feature not in exclude_features:
                                feature_dict[feature] = value

                        # assign indices to any features we have not seen before
                        for feature in feature_dict.keys():
                            if feature not in feature_names:
                                feature_names.append(feature)

                        # convert the feature dictionary into a feature vector
                        feature_vec = []
                        for feature, value in feature_dict.items():
                            idx = feature_names.index(feature)
                            if idx >= len(feature_vec):
                                feature_vec.extend(
                                    [0] * (idx - len(feature_vec) + 1))
                            feature_vec[idx] = value

                        # add the feature vector to the training set
                        training_set.append(feature_vec)

                        # add the label to the labels list
                        label = "benign"
                        if hashing:
                            hash_file = os.path.join(root, "hash.csv")
                            if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
                                with open(hash_file, "r") as rfi:
                                    hash_res = csv.reader(rfi).__next__()[0]
                                if hash_res in malicious:
                                    label = "malicious"
                        else:
                            if (package, version) in malicious:
                                label = "malicious"
                        labels.append(label)
                        if label == "malicious" and randomize == True:
                            malicious_len += 1

    # normalize length of feature vectors by extending with zeros
    num_features = len(feature_names)
    for i in range(len(training_set)):
        length = len(training_set[i])
        if length < num_features:
            training_set[i].extend([0] * (num_features - length))

    if randomize == True:
        benign_indices = [i for i, s in enumerate(
            training_set) if labels[i] == "benign"]
        benign_selected = random.sample(benign_indices, malicious_len)
        training_set_copy = []
        labels_copy = []
        for indx, s in enumerate(training_set):
            if indx in benign_selected or labels[indx] == "malicious":
                training_set_copy.append(s)
                labels_copy.append(labels[indx])

        training_set = training_set_copy
        labels = labels_copy
    
    start = timer()
    # train the classifier
    if classifier == "decision-tree":
        classifier = tree.DecisionTreeClassifier(criterion="entropy")
        classifier.fit(training_set, labels)
    elif classifier == "random-forest":
        classifier = RandomForestClassifier(criterion="entropy")
        classifier.fit(training_set, labels)
    elif classifier == "naive-bayes":
        classifier = naive_bayes.BernoulliNB()
        classifier.fit(training_set, labels)
    else:
        classifier = svm.OneClassSVM(
            gamma='scale', nu=nu, kernel='linear')
        classifier.fit([datum for i, datum in enumerate(
            training_set) if labels[i] == "benign"])  
    end = timer()
    diff = timedelta(seconds=end-start)
    
    if performance is not None: 
        with open(performance, "a+") as wfi:
            writer = csv.writer(wfi)
            writer.writerow([diff])

    # render the tree if requested; only applicable for decision trees
    if classifier == "decision-tree" and render:
        file, ext = os.path.splitext(render)
        if ext != ".png":
            print("Rendering tree to PNG requires a file name ending in .png")
            exit(1)
        outfile = Source(tree.export_graphviz(
            classifier, out_file=None, feature_names=feature_names), format="png")
        outfile.render(file, view=view, cleanup=True)

    # store the classifier and metadata
    with open(output, "wb") as f:
        pickle.dump({
            "feature_names": feature_names,
            "booleanize": booleanize,
            "positive": positive,
            "classifier": classifier
        }, f)


if __name__ == "__main__":
    argparse = argparse.ArgumentParser(
        description="Train a classifier")
    argparse.add_argument(
        "classifier", help="Type of classifier to be trained.", choices=["decision-tree", "random-forest", "naive-bayes", "svm"])
    argparse.add_argument(
        "malicious", help="CSV file listing known malicious package versions.")
    argparse.add_argument(
        "training_sets", help="Directories with features for package versions to train on.", nargs="*")
    argparse.add_argument(
        "-b", "--booleanize", help="Whether to booleanize feature vectors.", choices=["true", "false"], default="false")
    argparse.add_argument(
        "--hashing", help="Whether hashes are required to label malicious packages. Default is pairs of <package,version>", choices=["true", "false"], default="false")
    argparse.add_argument(
        "-x", "--exclude-features", help="List of features to exclude.", required=False, nargs="*", default=[])
    argparse.add_argument(
        "-n", "--nu", help="nu value for svm.", required=False, type=float, default=0.001)
    argparse.add_argument(
        "-o", "--output", help="Output file to store the pickled classifier in.", required=True)
    argparse.add_argument(
        "-p", "--positive", help="Whether to keep only positive values in features", choices=["true", "false"], default="false")
    argparse.add_argument(
        "-r", "--render", help="PNG file to render the decision tree to. Ignored for other types of classifiers.", required=False)
    argparse.add_argument(
        "--randomize", help="Balance datasets.", choices=["true", "false"], default="false")
    argparse.add_argument(
        "-v", "--view", help="View the decision tree graphically. Ignored unless --render is specified.", action="store_true")
    argparse.add_argument(
        "-l", "--leave_out", help="Training files to leave out", required=False, nargs="*", default=[])
    argparse.add_argument(
        "-u", "--until", help="Specify the date up to which samples should be considered for training.", required=False, default="2100-01-01T00:00:00.000Z")

    args = argparse.parse_args()
    booleanize = True if args.booleanize == "true" else False
    hashing = True if args.hashing == "true" else False
    positive = True if args.positive == "true" else False
    randomize = True if args.randomize == "true" else False
    until = parse_date(args.until)
    train_classifier(args.classifier, args.malicious, args.training_sets, args.output, booleanize, hashing, args.exclude_features,
                     args.nu, positive, args.render, randomize, args.view, args.leave_out, until)
    
    