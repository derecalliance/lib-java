## Library setup in IntelliJ
1. Clone the repo
2. Open the project in IntelliJ
3. Navigate to `derec-lib/impl/src/generated/java`
4. Right click the `generated` folder, and select "Mark Directory As" > "Unmark as Sources Root"
5. Then, the folders within `generated` should expand. Right click on `impl/src/generated/java` and select "Mark Directory As" > "Mark as Sources Root".
6. Mark `generated` as sources root as well by right clicking on `impl/src/generated` and selecting Mark Directory As" > "Mark as Sources Root". Now, both `generated` and `java` folders should be marked as sources roots (the folder icon turns blue).
8. Navigate to the root directory `derec-lib/`  and run `mvn clean compile package install` in the terminal
8.Navigate to `derec-lib/api` and run `mvn clean compile package install` in the terminal
9. Navigate to `derec-lib/impl` and run `mvn clean compile package install` in the terminal
