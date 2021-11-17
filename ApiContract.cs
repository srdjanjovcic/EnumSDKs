﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Xml;
using System.Collections.Generic;

namespace EnumSDKs
{
    /// <summary>
    /// Represents an API contract definition
    /// </summary>
    internal struct ApiContract
    {
        /// <summary>
        /// Name of the contract
        /// </summary>
        internal string Name;

        /// <summary>
        /// Version of the contract
        /// </summary>
        internal string Version;

        /// <summary>
        /// Constructor.
        /// </summary>
        private ApiContract(string name, string version)
        {
            Name = name;
            Version = version;
        }

        /// <summary>
        /// Returns true if this element is a "ContainedApiContracts" element. 
        /// </summary>
        internal static bool IsContainedApiContractsElement(string elementName) => string.Equals(elementName, Elements.ContainedApiContracts, StringComparison.Ordinal);

        internal static bool IsVersionedContentElement(string elementName) => string.Equals(elementName, Elements.VersionedContent, StringComparison.Ordinal);

        /// <summary>
        /// Given an XML element containing API contracts, read out all contracts within that element. 
        /// </summary>
        internal static void ReadContractsElement(XmlElement element, ICollection<ApiContract> apiContracts)
        {
            if (element != null && IsContainedApiContractsElement(element.Name))
            {
                // <ContainedApiContracts>
                //    <ApiContractCopy name="UAP" version="1.0.0.0" />
                // </ContainedApiContracts>
                foreach (XmlNode contractNode in element.ChildNodes)
                {
                    if (contractNode is XmlElement contractElement && string.Equals(contractNode.Name, Elements.ApiContractCopy, StringComparison.Ordinal))
                    {
                        apiContracts.Add(new ApiContract(
                            contractElement.GetAttribute(Attributes.Name),
                            contractElement.GetAttribute(Attributes.Version)
                        ));
                    }
                }
            }
        }

        /// <summary>
        /// Helper class with ApiContractCopy element names
        /// </summary>
        private static class Elements
        {
            /// <summary>
            /// Element containing a bucket of contracts
            /// </summary>
            public const string ContainedApiContracts = "ContainedApiContracts";

            /// <summary>
            /// Element representing an individual API contract
            /// </summary>
            public const string ApiContractCopy = "ApiContractCopy";

            /// <summary>
            /// Element representing a flag to indicate if the SDK content is versioned
            /// </summary>
            public const string VersionedContent = "VersionedContent";
        }

        /// <summary>
        /// Helper class with attribute names
        /// </summary>
        private static class Attributes
        {
            /// <summary>
            /// Name associated with this element
            /// </summary>
            public const string Name = "name";

            /// <summary>
            /// Version associated with this element
            /// </summary>
            public const string Version = "version";
        }
    }
}