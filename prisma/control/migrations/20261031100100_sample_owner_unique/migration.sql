-- One SAMPLE workspace per owner (the sample is created on click and owned only by that user).
CREATE UNIQUE INDEX "tenants_sample_owner_key" ON "tenants"("ownerIssuer", "ownerSubject") WHERE "kind" = 'SAMPLE';
