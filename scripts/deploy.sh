#!/usr/bin/env bash

aws cloudformation deploy \
    --template-file ./packaged-template.yaml \
    --stack-name MacieRemediationLambdaStack \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides SafeBucketName=$MACIE_REMEDIATOR_SAFE_BUCKET_NAME