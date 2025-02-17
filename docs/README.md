# Case-Based Reasoning

## Overview

This is a project for a subject called "Sistemas Expertos" (Expert Systems) that accounted for 15% of the final grade. It was made by a team of 2 people. The submission took place on Sunday, the 10th of November of 2024, and earned a grade of 10 out of 10 points.

## Project Summary

For this project we had to create a case-based reasoning system that would give a danger grade [0-10] and the type of attack [`NETWORK`, `ADJACENT NETWORK` or `LOCAL`] to a new [CVE (Common Vulnerabilities and Exposures)](https://www.cve.org/) vulnerability report from a [database of previous reports](../datos/base_casos.json). The entire CBR cycle had to be implemented, so the revision and retention steps were also part of the system. This was implemented with the library [CBRkit](https://github.com/wi2trier/cbrkit).
