## Library setup in IntelliJ
1. Clone the repo
2. Open the project in IntelliJ
3. In the file strucure on the screen, navigate to `impl/src/generated`
4. Right-click the `generated` folder, and select "Mark Directory As" > "Unmark as Sources Root"
5. Then, the folders within `generated` should expand. Right-click on `impl/src/generated/java` and select "Mark 
   Directory As" > "Sources Root".
6. Mark `generated` as sources root as well by right-clicking on `impl/src/generated` and selecting Mark Directory 
   As" > "Sources Root". Now, both `generated` and `java` folders should be marked as sources roots (the folder icon turns blue).
8. In the terminal, navigate to the root directory `dereclib`  and run `mvn clean compile package install`
9. In the terminal, `dereclib/api` and run `mvn clean compile package install`
10. In the terminal, `dereclib/impl` and run `mvn clean compile package install`

## Formatting Files
1. Run `mvn validate` in the `impl` directory to format all files if changes are made.
